import { User } from "../models/user.model";
import bcrypt from "bcryptjs";
import { Request, Response } from "express";

class userController {
  // create User
  async createUser(req: Request, res: Response) {
    try {
      const salt = await bcrypt.genSalt(10);
      const hashed = await bcrypt.hash(req.body.password, salt);

      const newUser = await new User({
        name: req.body.name,
        email: req.body.email,
        password: hashed,
      });

      const user = await newUser.save();
      res.json(user);
    } catch (error) {
      console.log(error);
    }
  }
  // GetAllUsers

  async getAllUsers(req: Request, res: Response) {
    try {
      const users = await User.find();
      res.json(users);
    } catch (error) {
      console.error(error);
    }
  }
  // find User
  async findUser(req: Request, res: Response) {
    try {
      const user = await User.findById(req.params.id);
      res.json(user);
    } catch (error) {
      res.json(error);
    }
  }
  // Remove user
  async removeUser(req: Request, res: Response) {
    try {
      const deletedUser = await User.findByIdAndDelete(req.params.id);
      res.json(deletedUser);
    } catch (error) {
      res.json(error);
    }
  }

  async updateUser(req: Request, res: Response) {
    try {
      const updatedUser = await User.findByIdAndUpdate(
        req.params.id,
        {
          $set: req.body,
        },
        { new: true }
      );
      res.json(updatedUser);
    } catch (error) {
      res.json(error);
    }
  }
}

export default new userController();
