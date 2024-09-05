const mongoose = require('mongoose');

const Schema = mongoose.Schema;

const blogSchema = new Schema({
  title: {
    type: String,
    required: true,
    unique: true
  },
  description: {
    type: String
  },
  author: {
    type: Schema.Types.ObjectId, ref: 'User'
  },
  state: {
    type: String,
    enum: ['draft', 'published'], // Example states
    default: 'draft'
  },
  read_count: {
    type: Number,
    default: 0
  },
  reading_time: {
    type: String
  },
  tags: {
    type: [String]
  },
  body: {
    type: String,
    required: true
  },
  timestamps: {
    type: Date,
    default: Date.now
  } // Automatically adds createdAt and updatedAt fields
});

const Blog = mongoose.model('Blog', blogSchema);

module.exports = Blog;