const express = require("express");
const router = express.Router();
const Blog = require("../models/Blog");



// GET /
// HOME
router.get("", async (req, res) => {
  try {
    const locals = {
      title: "BlogSphere",
      author: "yasir",
    };

    let perPage = 20;
    let page = req.query.page || 1;

    const data = await Blog.aggregate([
      { $match: { state: 'published' } }, // Filter to show only published posts
      { $sort: { createdAt: -1 } }
    ])
      .skip(perPage * page - perPage)
      .limit(perPage)
      .exec();

    const count = await Blog.countDocuments({ state: 'published' }); // Count only published posts
    const nextPage = parseInt(page) + 1;
    const hasNextPage = nextPage <= Math.ceil(count / perPage);

    res.render("home", {
      locals,
      data,
      current: page,
      nextPage: hasNextPage ? nextPage : null,
      currentRoute: "/",
    });
  } catch (err) {
    console.log(err);
    res.status(500).send("An error occurred while fetching the posts.");
  }
});

/**
 * GET
 * Post
 */
router.get("/allPost/:id", async (req, res) => {
  try {
    let slug = req.params.id;

    const data = await Blog.findByIdAndUpdate(
      { _id: slug },
      { $inc: { read_count: 1 } },  // Increment the read_count by 1
      { new: true }  // Return the updated document
    );

    if (!data) {
      return res.status(404).send("This Post was not found, Try another Post!");
    }
    const locals = {
      title: data.title
    }

    res.render("post", { locals, data })
  } catch (err) {
    console.log(err);
  }
})


/**
 * Post /
 * Post   SearchTerm
 */
router.post("/search", async (req, res) => {
  try {
    const locals = {
      title: "Search",
      description: "",
    };
    let searchTerm = req.body.searchTerm;
    const searchNoSpecialChar = searchTerm.replace(/[^a-zA-Z0-9\s]/g, "");
    const regex = new RegExp(searchNoSpecialChar.split(' ').join('.*'), "i");

    const data = await Blog.find({
      $or: [
        {
          title: { $regex: regex },
        },
        {
          tags: { $regex: regex }
        },
        {
          body: { $regex: regex },
        },
      ],
    });
    res.render("search", { locals, data });
  } catch (error) {
    console.log(error);
    res.status(500).send("An error occurred during the search.");
  }
});



router.get("/about", (req, res) => {
  res.render("about", {
    currentRoute: "/about",
  });
});


router.get("/contact", (req, res) => {
  res.render("contact", {
    currentRoute: "/contact",
  });
});


module.exports = router;