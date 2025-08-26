const express = require("express");
const router = express.Router();
const User = require("../models/User");
const Blog = require("../models/Blog");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const logger = require("../config/logger"); // Import the logger
const adminLayout = "../views/layouts/admin";
const jwtSecret = process.env.JWT_SECRET;

/**
 * Generate User Token
 */
const generateToken = (userId) => {
  return jwt.sign({ userId }, jwtSecret, { expiresIn: '1h' }); // Token expires in 1 hour
};

/**
 * Check if Logged In
 */
const authMiddleware = async (req, res, next) => {
  const token = req.cookies.token;

  if (!token) {
    logger.warn("Unauthorized session attempt without token");
    return res.status(401).json({ message: "Unauthorized session!" });
  }

  try {
    const decoded = jwt.verify(token, jwtSecret);
    req.userId = decoded.userId;

    const user = await User.findById(req.userId).select('firstname lastname email');
    if (!user) {
      logger.warn(`Unauthorized session attempt with invalid user ID: ${req.userId}`);
      return res.status(401).json({ message: "Unauthorized session!" });
    }

    req.user = user;
    next();
  } catch (err) {
    logger.error(`Token verification failed: ${err.message}`);
    return res.status(401).json({ message: "Unauthorized session!" });
  }
};

/**
 * GET HOME
 * Admin Sign up page
 */
router.get("/admin", async (req, res) => {
  try {
    const locals = {
      title: "Admin Panel",
      description: "Admin page",
    };
    res.render("admin/index", { locals, layout: adminLayout });
  } catch (error) {
    logger.error(`Error rendering admin signup page: ${error.message}`);
    res.status(500).send("An error occurred while rendering the page.");
  }
});

/**
 * GET HOME
 * Admin -Login page
 */
router.get("/admin-login", async (req, res) => {
  try {
    const locals = {
      title: "Admin Panel Login",
      description: "Admin page",
    };
    res.render("admin/login", { locals, layout: adminLayout });
  } catch (error) {
    logger.error(`Error rendering admin login page: ${error.message}`);
    res.status(500).send("An error occurred while rendering the page.");
  }
});

/**
 * POST
 * Admin Register
 */
router.post("/register", async (req, res) => {
  try {
    const { firstname, lastname, username, password } = req.body;
    const hashedpassword = await bcrypt.hash(password, 10);

    try {
      const user = await User.create({
        firstname,
        lastname,
        username,
        password: hashedpassword,
      });
      logger.info(`User registered successfully: ${user.username}`);
      res.status(201).json({ message: "User Created", user });
    } catch (error) {
      if (error.code === 11000) {
        logger.warn(`User registration failed - duplicate username: ${username}`);
        res.status(409).json({ message: "Username already in use" });
      } else {
        logger.error(`Error registering user: ${error.message}`);
        res.status(500).json({ message: "Internal server error!" });
      }
    }
  } catch (error) {
    logger.error(`Error hashing password during registration: ${error.message}`);
    res.status(500).json({ message: "Internal server error!" });
  }
});

/**
 * POST
 * Admin Check Login
 */
router.post("/admin", async (req, res) => {
  try {
    const { username, password } = req.body;
    const user = await User.findOne({ username });

    if (!user) {
      logger.warn(`Failed login attempt with invalid username: ${username}`);
      return res.status(401).json({ message: "Invalid Credentials!" });
    }

    const isPasswordValid = await bcrypt.compare(password, user.password);

    if (!isPasswordValid) {
      logger.warn(`Failed login attempt with invalid password for username: ${username}`);
      return res.status(401).json({ message: "Invalid Credentials!" });
    }

    const token = generateToken(user._id);
    res.cookie("token", token, { httpOnly: true });
    logger.info(`User logged in successfully: ${username}`);
    res.redirect("/dashboard");
  } catch (error) {
    logger.error(`Error during login process: ${error.message}`);
    res.status(500).json({ message: "Internal server error!" });
  }
});

/**
 * GET
 * Admin Dashboard
 */
router.get("/dashboard", authMiddleware, async (req, res) => {
  try {
    const locals = {
      title: "Admin Dashboard",
      description: "The admin dashboard!",
    };
    const data = await Blog.find();
    res.render("admin/dashboard", {
      locals,
      data,
      layout: adminLayout,
    });
    logger.info("Admin dashboard accessed");
  } catch (err) {
    logger.error(`Error retrieving dashboard data: ${err.message}`);
    res.status(500).send("An error occurred while loading the dashboard.");
  }
});

/**
 * GET
 * Admin -GET All Posts
 */
router.get("/post/:id", authMiddleware, async (req, res) => {
  try {
    let slug = req.params.id;

    const data = await Blog.findByIdAndUpdate(
      { _id: slug },
      { $inc: { read_count: 1 } },  // Increment the read_count by 1
      { new: true }  // Return the updated document
    );

    if (!data) {
      logger.warn(`Post not found for ID: ${slug}`);
      return res.status(404).send("This Post was not found, Try another Post!");
    }

    const locals = {
      title: data.title,
    }
    res.render("admin/post", { locals, data, layout: adminLayout });
    logger.info(`Post viewed: ${data.title} (ID: ${slug})`);
  } catch (error) {
    logger.error(`Error retrieving post data for ID: ${slug} - ${error.message}`);
    res.status(500).send("An error occurred while trying to retrieve the post.");
  }
});

/**
 * GET
 * Admin Create New Post
 */
router.get("/add-post", authMiddleware, async (req, res) => {
  try {
    const locals = {
      title: "Add post",
      description: "The admin dashboard!",
    };
    const data = await Blog.find();
    res.render("admin/add-post", {
      locals,
      data,
      layout: adminLayout,
      user: req.user
    });
    logger.info("Add post page accessed");
  } catch (err) {
    logger.error(`Error accessing add post page: ${err.message}`);
    res.status(500).send("An error occurred while loading the page.");
  }
});

/**
 * POST /
 * Admin Create New Post
 */
router.post("/add-post", authMiddleware, async (req, res) => {
  const { title, description, tags, body } = req.body;
  const author = req.userId; // Use the authenticated user's ID from the middleware

  let state = 'published'; // Default state

  const newPost = new Blog({
    title,
    description,
    author,  // Automatically set the author field
    state,
    tags: tags ? tags.split(',').map(tag => tag.trim()) : [],
    body
  });

  newPost.save()
    .then(() => {
      logger.info(`New post created: ${title}`);
      res.redirect('/dashboard');
    })
    .catch(err => {
      logger.error(`Error saving new post: ${err.message}`);
      res.status(500).send("An error occurred while saving the post.");
    });
});

/**
 * GET
 * Admin Edit post
 */
router.get("/edit-post/:id", authMiddleware, async (req, res) => {
  try {
    const locals = {
      title: "Edit Post",
      description: "The admin dashboard!"
    };
    const data = await Blog.findOne({ _id: req.params.id });

    res.render('admin/edit-post', {
      locals,
      data,
      layouts: adminLayout
    })
    logger.info(`Edit post page accessed for post ID: ${req.params.id}`);
  } catch (err) {
    logger.error(`Error accessing edit post page for post ID: ${req.params.id} - ${err.message}`);
    res.status(500).send("An error occurred while loading the page.");
  }
});

/**
 * PUT
 * Admin Edit post
 */
router.put("/edit-post/:id", authMiddleware, async (req, res) => {
  try {
    await Blog.findByIdAndUpdate(req.params.id, {
      title: req.body.title,
      author: req.body.author,
      body: req.body.body,
      state: req.body.state, // This will update the state of the post
      updatedat: Date.now()
    });

    logger.info(`Post updated: ${req.body.title} (ID: ${req.params.id})`);
    res.redirect('/dashboard');
  } catch (err) {
    logger.error(`Error updating post ID: ${req.params.id} - ${err.message}`);
    res.status(500).send("An error occurred while updating the post.");
  }
});

/**
 * Delete
 * Admin -Delete post
 */
router.delete("/delete-post/:id", authMiddleware, async (req, res) => {
  try {
    await Blog.deleteOne({ _id: req.params.id });
    logger.info(`Post deleted: ID ${req.params.id}`);
    res.redirect('/dashboard');
  } catch (err) {
    logger.error(`Error deleting post ID: ${req.params.id} - ${err.message}`);
    res.status(500).send("An error occurred while deleting the post.");
  }
});

/**
 * GET
 * Admin - Logout
 */
router.get('/logout', (req, res) => {
  res.clearCookie('token');
  logger.info("User logged out");
  res.redirect('/');
});

module.exports = router;