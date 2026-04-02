const express = require("express");
const router = express.Router();
const authController = require("../controllers/authController");

// Register and Login route
router.post("/register", authController.register);
router.post("/login", authController.login);
router.post("/refresh", authController.refresh);

// Protected route example (test)
// router.post("/me", authMiddleware, authController.me);

// Logout route
router.post("/logout", authController.logout);

module.exports = router;