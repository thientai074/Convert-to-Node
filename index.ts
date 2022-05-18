require('dotenv').config()
import express from "express";
import mongoose from "mongoose";
import authRouter from "./routes/auth.route";
import userRouter from "./routes/user.router";

const app = express();

app.use(express.json());

const connectDB = async () => {
  try {
    await mongoose.connect(
      "mongodb+srv://thientai074:thientai077@cluster0.fn5pj.mongodb.net/Convert?authSource=admin&replicaSet=atlas-y3ya0g-shard-0&w=majority&readPreference=primary&retryWrites=true&ssl=true"
    );
    console.log("Ket noi Database thanh cong !!!");
  } catch (error) {
    console.error(error);
  }
};
connectDB();

app.use("/api", authRouter);
app.use("/api", userRouter);

const PORT = 4000;

app.listen(PORT, () => {
  console.log(`Server listening on port ${PORT}`);
});
