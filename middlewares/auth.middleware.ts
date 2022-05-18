const jwt = require("jsonwebtoken");
import { Request, Response, NextFunction } from "express";

const verifyTokenAndAdmin = (
  req: Request,
  res: Response,
  next: NextFunction
) => {
  const authHeader = req.header("Authorization");
  const token = authHeader && authHeader.split(" ")[1];

  if (!token) {
    return res.json({
      success: false,
      message: "Access Token not found",
    });
  }

  try {
    const decoded = jwt.verify(token, "hello");
    if (decoded.role === "admin") {
      next();
    } else {
      res.json("You are not allowed to do that");
    }
  } catch (error) {
    console.log(error);
    return res.json({
      success: false,
      message: "Invalid Token",
    });
  }
};

const verifyTokenAndAuthorization = (
  req: Request,
  res: Response,
  next: NextFunction
) => {
  const authHeader = req.header("Authorization");
  const token = authHeader && authHeader.split(" ")[1];

  if (!token) {
    return res.json({
      success: false,
      message: "Access Token not found",
    });
  }

  try {
    const decoded = jwt.verify(token, "hello");
    if (decoded.id === req.params.id || decoded.role === "admin") {
      console.log("decoded", decoded);
      next();
    } else {
      res.json("You are not allowed to do that");
    }
  } catch (error) {
    console.log(error);
    return res.json({
      success: false,
      message: "Invalid Token",
    });
  }
};

module.exports = {
  verifyTokenAndAdmin,
  verifyTokenAndAuthorization,
};
