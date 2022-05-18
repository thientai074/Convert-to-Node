import express from "express";
const router = express.Router();
const {
  verifyTokenAndAuthorization,
  verifyTokenAndAdmin,
} = require("../middlewares/auth.middleware");
import userController from "../controlllers/user.controller";

// Find User
router.get("/user/:id",verifyTokenAndAuthorization, userController.findUser);

// // Update User
router.put("/user/:id",verifyTokenAndAuthorization, userController.updateUser);

// // Delete User
router.delete("/user/:id",verifyTokenAndAuthorization, userController.removeUser);

// Get all Users
router.get("/user",verifyTokenAndAdmin , userController.getAllUsers);

// Create User
router.post("/user", userController.createUser);

export default router;
