const express = require("express");
const router = express.Router();
const Blog = require("../models/Blog");
const Details = require("../models/Details");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const logger = require("../config/logger"); // Import the logger

const userLayout = "../views/layouts/users";
const jwtSecret = process.env.JWT_SECRET;

/**
 * Querying Posts by User ID
 */
const getUserPosts = async (userId) => {
    try {
        const posts = await Blog.find({ author: userId }).sort({ createdAt: -1 }); // Fetch posts and sort by date (newest first)
        logger.info(`Posts fetched for user ID: ${userId}`);
        return posts;
    } catch (error) {
        logger.error(`Error fetching user posts: ${error.message}`);
        throw error;
    }
};

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
        logger.warn("Unauthorized access attempt without token");
        return res.status(401).json({ message: "Unauthorized session!" });
    }

    try {
        const decoded = jwt.verify(token, jwtSecret);
        req.userId = decoded.userId;

        const user = await Details.findById(req.userId).select('firstname lastname email');
        if (!user) {
            logger.warn(`Unauthorized access attempt with invalid user ID: ${req.userId}`);
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
 * GET
 * User route
 */
router.get("/User", async (req, res) => {
    try {
        const locals = {
            title: "User Sign Up",
            description: "User sign Up page for users",
        };
        res.render("users/index", { locals, layout: userLayout });
        logger.info("User sign-up page rendered");
    } catch (error) {
        logger.error(`Error rendering user sign-up page: ${error.message}`);
        res.status(500).send("An error occurred while rendering the page.");
    }
});

/**
 * POST
 * User Register
 */
router.post("/registeruser", async (req, res) => {
    try {
        const { firstname, lastname, email, password } = req.body;
        const hashedpassword = await bcrypt.hash(password, 10);

        try {
            const user = await Details.create({
                firstname,
                lastname,
                email,
                password: hashedpassword,
            });
            logger.info(`User registered successfully: ${user.email}`);
            res.status(201).json({ message: "User Created", user });
        } catch (error) {
            logger.error(`Error registering user: ${error.message}`);
            res.status(500).json({ message: "Internal server error!" });
        }
    } catch (error) {
        logger.error(`Error hashing password during registration: ${error.message}`);
        res.status(500).json({ message: "Internal server error!" });
    }
});

/**
 * GET
 * Users - Login Page
 */
router.get("/SignIn", async (req, res) => {
    try {
        const locals = {
            title: "User Login",
            description: "User Login page",
        };
        res.render("users/signIn", { layout: userLayout });
        logger.info("User login page rendered");
    } catch (error) {
        logger.error(`Error rendering user login page: ${error.message}`);
        res.status(500).send("An error occurred while rendering the page.");
    }
});

/**
 * POST
 * Users Check Login
 */
router.post("/login", async (req, res) => {
    try {
        const { email, password } = req.body;

        const user = await Details.findOne({ email });

        if (!user) {
            logger.warn(`Failed login attempt with invalid email: ${email}`);
            return res.status(401).json({ message: "Invalid Credentials!" });
        }

        const isPasswordValid = await bcrypt.compare(password, user.password);

        if (!isPasswordValid) {
            logger.warn(`Failed login attempt with invalid password for email: ${email}`);
            return res.status(401).json({ message: "Invalid Credentials!" });
        }

        const token = generateToken(user._id);
        res.cookie("token", token, { httpOnly: true });
        logger.info(`User logged in successfully: ${email}`);
        res.redirect("/user-dashboard");
    } catch (error) {
        logger.error(`Error during login process: ${error.message}`);
        res.status(500).json({ message: "Internal server error!" });
    }
});

/**
 * GET
 * Users -Dashboard
 */
router.get('/user-dashboard', authMiddleware, async (req, res) => {
    try {
        const locals = {
            title: "Dashboard",
            description: "User Dashboard",
            firstname: req.user.firstname,
        };
        const userId = req.user._id; // Assuming user ID is stored in req.user after authentication
        const posts = await getUserPosts(userId);

        res.render("users/user_dashboard", { locals, posts, layout: userLayout }); // Render dashboard template and pass the posts
        logger.info(`User dashboard accessed for user ID: ${userId}`);
    } catch (error) {
        logger.error(`Error fetching posts for dashboard: ${error.message}`);
        res.status(500).send('Error fetching posts');
    }
});

/**
 * GET
 * USer -Create New Post
 */
router.get("/create-new-post", authMiddleware, (req, res) => {
    try {
        const locals = {
            title: "Create A New Post",
            description: "Users Creating New Posts",
        };
        res.render("users/create-new-post", { locals, layout: userLayout, user: req.user });
        logger.info("Create new post page accessed");
    } catch (error) {
        logger.error(`Error accessing create new post page: ${error.message}`);
        res.status(500).send('Error Creating New posts, Please Try Again!');
    }
});

/**
 * POST
 * USer -Create New Post
 */
router.post('/create-new-post', authMiddleware, (req, res) => {
    const { title, description, tags, body } = req.body;
    const author = req.userId; // Use the authenticated user's ID from the middleware

    let state = 'draft'; // Default state

    const newPost = new Blog({
        title,
        description,
        author,
        state,
        tags: tags ? tags.split(',').map(tag => tag.trim()) : [],
        body,
    });

    newPost.save()
        .then(() => {
            logger.info(`New post created by user ID: ${author}, title: ${title}`);
            res.redirect('/user-dashboard');
        })
        .catch(err => {
            logger.error(`Error saving new post: ${err.message}`);
            res.status(500).send('Error creating post, please try again.');
        });
});

/**
 * GET
 * User - Post
 */
router.get("/posts/:id", authMiddleware, async (req, res) => {
    try {
        let slug = req.params.id;

        // Find the blog post by ID and increment the read_count by 1
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
        };
        res.render("users/posts", { locals, data, layout: userLayout });
        logger.info(`Post viewed: ${data.title} (ID: ${slug})`);
    } catch (error) {
        logger.error(`Error retrieving post data for ID: ${slug} - ${error.message}`);
        res.status(500).send("An error occurred while trying to retrieve the post.");
    }
});

/**
 * GET
 * User -Edit post
 */
router.get("/edit-posts/:id", authMiddleware, async (req, res) => {
    try {
        const locals = {
            title: "Edit Your Post",
            description: "The admin dashboard!",
        };
        const data = await Blog.findOne({ _id: req.params.id });
        res.render('users/edit-posts', {
            locals,
            data,
            layouts: userLayout,
        });
        logger.info(`Edit post page accessed for post ID: ${req.params.id}`);
    } catch (err) {
        logger.error(`Error accessing edit post page for post ID: ${req.params.id} - ${err.message}`);
        res.status(500).send('An error occurred while loading the page.');
    }
});

/**
 * PUT
 * User Edit post
 */
router.put("/edit-posts/:id", authMiddleware, async (req, res) => {
    try {
        await Blog.findByIdAndUpdate(req.params.id, {
            title: req.body.title,
            description: req.body.description,
            tags: req.body.tags,
            body: req.body.body,
            timestamps: Date.now(),  // This will automatically update the `updatedAt` field
        });
        logger.info(`Post updated: ID ${req.params.id}`);
        res.redirect("/user-dashboard");
    } catch (err) {
        logger.error(`Error updating post ID: ${req.params.id} - ${err.message}`);
        res.status(500).send("An error occurred while trying to update the post.");
    }
});

/**
 * DELETE
 * User -Delete post
 */
router.delete("/delete-posts/:id", authMiddleware, async (req, res) => {
    try {
        await Blog.deleteOne({ _id: req.params.id });
        logger.info(`Post deleted: ID ${req.params.id}`);
        res.redirect('/user-dashboard');
    } catch (err) {
        logger.error(`Error deleting post ID: ${req.params.id} - ${err.message}`);
        res.status(500).send("An error occurred while deleting the post.");
    }
});

/**
 * GET
 * Users Logout
 */
router.get('/logout', (req, res) => {
    res.clearCookie('token');
    logger.info("User logged out");
    res.redirect('/');
});

module.exports = router;