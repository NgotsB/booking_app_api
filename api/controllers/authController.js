import User from "../models/User.js";
import bcrypt from "bcryptjs";
import { createError } from "../utils/error.js";
import jwt from "jsonwebtoken";

//Register function
export const register = async (req, res, next) => {
  try {
    if ((req.body.password, req.body.username)) {
      const salt = bcrypt.genSaltSync(10);
      const hash = bcrypt.hashSync(req.body.password, salt);

      const newUser = new User({
        username: req.body.username,
        email: req.body.email,
        password: hash,
      });
      await newUser.save();
      res.status(201).send("New user has been created.");
    }
    // else {
    //   res.status(403).json("Please provide a password or username");
    // }
  } catch (err) {
    next(err);
  }
};
//Log-in function
export const login = async (req, res, next) => {
  try {
    const user = await User.findOne({ username: req.body.username });
    if (!user) {
      return next(createError(404, "User not found!"));
      // return res.status(404).json("User not found!");
    }

    const isPasswordCorrect = await bcrypt.compare(
      req.body.password,
      user.password
    );
    if (!isPasswordCorrect) {
      return next(createError(400, "Wrong username or password!"));
      //return res.status(400).json("Please enter correct password!");
    }

    const payload = {
      id: user._id,
      isAdmin: user.isAdmin,
    };
    const token = jwt.sign(payload, process.env.JWT, { expiresIn: "1d" });
    const { password, isAdmin, ...otherDetails } = user._doc;
    res
      .cookie("access_token", token, {
        httpOnly: true,
      })
      .status(200)
      .json({ ...otherDetails });
  } catch (err) {
    next(err);
  }
};
