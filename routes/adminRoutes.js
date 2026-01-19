const express = require("express");
const User = require("../models/User");
const auth = require("../middleware/authMiddleware");
const role = require("../middleware/roleMiddleware");

const router = express.Router();

// Get all users (Admin only)
router.get("/users", auth, role("admin"), async (req, res) => {
  const users = await User.find().select("-password");
  res.json(users);
});

router.get("/users", auth, role("admin"), async (req, res) => {
  const page = Number(req.query.page) || 1;
  const limit = 5;
  const skip = (page - 1) * limit;

  const users = await User.find()
    .select("-password")
    .skip(skip)
    .limit(limit);

  const total = await User.countDocuments();

  res.json({
    page,
    totalPages: Math.ceil(total / limit),
    users
  });
});


module.exports = router;
