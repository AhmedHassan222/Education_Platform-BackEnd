import { userModel } from "../../../DB/Models/user.model.js";
import { comparePassword, hashingPassword } from "../../utils/hashing.js";
import { generateToken } from "../../utils/tokenFunctions.js";
import bcrypt from "bcrypt";
import { nanoid } from "nanoid";
import { systemRoles } from "../../utils/systemRoles.js";
import { courseModel } from "../../../DB/Models/course.model.js";
import { ApiFeature } from "../../utils/apiFeature.js";
import cloudinary from "../../utils/cloudinaryConfigration.js";

// ________________________signUp________________________

export const signUp = async (req, res, next) => {
  const {
    fullName,
    email,
    password,
    repassword,
    phoneNumber,
    gender,
    parentsPhoneNumber,
    stage,
    grade,
  } = req.body;

  if (password !== repassword) {
    return next(new Error("password must match repassword", { cause: 401 }));
  }

  const existingUser = await userModel.findOne({ email });
  if (existingUser) {
    return next(new Error("Email Already Exist", { cause: 401 }));
  }

  const newUser = new userModel({
    fullName,
    email,
    password,         // hashed by the pre-save hook in userModel
    gender,
    phoneNumber,
    parentsPhoneNumber,
    stage,
    grade,
    isConfirmed: true,
  });

  await newUser.save();

  return res.status(201).json({ message: "Sign up success, please try to login", success: true });
};

// ______________________________login________________________________

export const login = async (req, res, next) => {
  const { email, password } = req.body;

  const user = await userModel.findOne({ email, isConfirmed: true });
  if (!user) {
    return next(new Error("Invalid email or password", { cause: 400 }));
  }

  const match = bcrypt.compareSync(password, user.password);
  if (!match) {
    return next(new Error("Invalid email or password", { cause: 401 }));
  }

  const token = generateToken({
    payload: {
      _id: user._id,
      fullName: user.fullName,
      role: user.role,
      email: user.email,
      isLogedIn: true,
      isConfirmed: user.isConfirmed,
    },
  });

  if (!token) {
    return next(new Error("Token generation failed", { cause: 500 }));
  }

  // Persist login state and token on the user document
  const loggedIn = await userModel.findByIdAndUpdate(
    user._id,
    { isLogedIn: true, token },
    { new: true }
  );

  if (!loggedIn) {
    return next(new Error("Login failed, please try again"));
  }

  return res.status(200).json({ message: "Login success", token, success: true });
};

// ________________________forgetPassword________________________

export const forgetPass = async (req, res, next) => {
  const { email } = req.body;

  const emailExist = await userModel.findOne({ email });
  if (!emailExist) {
    return next(new Error("Invalid email", { cause: 401 }));
  }

  const code = nanoid(5);
  const codeHash = hashingPassword(code, parseInt(process.env.SALT_ROUNDS));

  const token = generateToken({
    payload: {
      email: emailExist.email,
      code: codeHash,
      changePassAt: Date.now(),
    },
  });

  if (!token) {
    return next(new Error("Token generation failed, please try again", { cause: 500 }));
  }

  const resetPasswordURL = `${req.protocol}://${req.headers.host}/auth/resetPass/${token}`;

  const emailSent = await sendEmail({
    to: emailExist.email,
    subject: "Reset Password",
    message: emailTemplate({
      link: resetPasswordURL,
      linkData: "Click To Reset",
      subject: "Reset Password",
    }),
  });

  if (!emailSent) {
    return next(new Error("Failed to send email, please try again", { cause: 409 }));
  }

  await userModel.findOneAndUpdate(
    { email },
    { code: codeHash, changePassAt: Date.now() },
    { new: true }
  );

  return res.status(201).json({ message: "Please check your email", resetPasswordURL });
};

// ________________________ResetPassword________________________

export const resetPassword = async (req, res, next) => {
  const { token } = req.params;
  const { newPassword } = req.body;

  const decode = decodeToken({ payload: token });

  if (!decode?.code) {
    return next(new Error("Invalid or expired token, please try again", { cause: 500 }));
  }

  const user = await userModel.findOne({ email: decode.email, code: decode.code });
  if (!user) {
    return next(new Error("Password already reset, please try to login", { cause: 401 }));
  }

  // Hash the new password explicitly before saving to be safe
  user.password = hashingPassword(newPassword, parseInt(process.env.SALT_ROUNDS));
  user.code = null;
  user.token = null;
  user.changePassAt = Date.now();

  const saved = await user.save();
  if (!saved) {
    return next(new Error("Failed to reset password, please try again", { cause: 500 }));
  }

  return res.status(200).json({ message: "Done, please try to login" });
};

// ______________________changePassword______________________

export const changePass = async (req, res, next) => {
  const { _id } = req.user;
  const { oldPass, newPass } = req.body;

  if (oldPass === newPass) {
    return next(new Error("Old password cannot equal new password", { cause: 400 }));
  }

  const user = await userModel.findById(_id);
  if (!user) {
    return next(new Error("User not found, please try to login", { cause: 400 }));
  }

  const match = comparePassword(oldPass, user.password);
  if (!match) {
    return next(new Error("Wrong old password", { cause: 400 }));
  }

  user.password = newPass;   // hashed by the pre-save hook
  const saved = await user.save();

  if (!saved) {
    return next(new Error("Failed to change password, please try again", { cause: 500 }));
  }

  return res.status(200).json({ message: "Done, please try to login" });
};

// _______________________uploadProfilePicture___________________

export const uploadProfilePicture = async (req, res, next) => {
  const { _id } = req.user;

  if (!req.file) {
    return next(new Error("Please upload a profile image", { cause: 400 }));
  }

  const user = await userModel.findById(_id);
  if (!user) {
    return next(new Error("User not found", { cause: 404 }));
  }

  // Remove old profile image from Cloudinary if it exists
  if (user.profileImage?.public_id) {
    await cloudinary.uploader.destroy(user.profileImage.public_id);
  }

  const { secure_url, public_id } = await cloudinary.uploader.upload(req.file.path, {
    folder: `${process.env.ONLINE_PLATFORM_FOLDER}/Profile/${user.fullName}/${user.email}`,
  });

  req.ImagePath = `${process.env.ONLINE_PLATFORM_FOLDER}/Profile/${user.fullName}/${user.email}`;

  const updatedUser = await userModel.findByIdAndUpdate(
    _id,
    { profileImage: { secure_url, public_id } },
    { new: true }
  );

  if (!updatedUser) {
    return next(new Error("Upload failed, please try again", { cause: 500 }));
  }

  return res.status(200).json({ message: "Done" });
};

// ====================updateUser========================

export const updateUser = async (req, res, next) => {
  const { userId } = req.query;
  const { fullName, stage, subjecTeacher } = req.body;

  const user = await userModel.findById(userId);
  if (!user) {
    return next(new Error("Invalid user id, please try again", { cause: 404 }));
  }

  const updateFields = {};
  if (fullName) updateFields.fullName = fullName;
  if (stage) updateFields.stage = stage;
  if (subjecTeacher) updateFields.subjecTeacher = subjecTeacher;
  updateFields.updatedAt = new Date();

  const updatedUser = await userModel.findByIdAndUpdate(
    userId,
    { $set: updateFields },
    { new: true, runValidators: true }
  );

  if (!updatedUser) {
    return next(new Error("Update failed", { cause: 401 }));
  }

  return res.status(200).json({ message: "User updated successfully", user: updatedUser });
};

// =============================addTeacher======================

export const addTeacher = async (req, res, next) => {
  const {
    fullName,
    email,
    password,
    repassword,
    phoneNumber,
    gender,
    subjecTeacher,
    stage,
  } = req.body;
  const { courseId } = req.query;

  if (password !== repassword) {
    return next(new Error("password must match repassword", { cause: 401 }));
  }

  const existingUser = await userModel.findOne({ email });
  if (existingUser) {
    return next(new Error("Email Already Exist", { cause: 401 }));
  }

  const course = await courseModel.findById(courseId);
  if (!course) {
    return next(new Error("Invalid course id", { cause: 401 }));
  }

  const teacher = new userModel({
    fullName,
    email,
    password,    // hashed by the pre-save hook
    phoneNumber,
    gender,
    subjecTeacher,
    courseId,
    stage,
    isConfirmed: true,
    role: systemRoles.TEACHER,
  });

  await teacher.save();

  return res.status(200).json({ message: "Done, please try to login" });
};

// ================deleteTeacher==================

export const deleteTeacher = async (req, res, next) => {
  const { email } = req.body;
  const { teacherId } = req.query;

  const user = await userModel.findOneAndDelete({
    email,
    _id: teacherId,
    role: "Teacher",
  });

  if (!user) {
    return next(new Error("Invalid email or id", { cause: 401 }));
  }

  return res.status(200).json({ message: "Done" });
};

// ====================getTeachers====================

export const getTeacher = async (req, res, next) => {
  const apiFeaturesInstance = new ApiFeature(userModel.find({ role: systemRoles.TEACHER }), req.query)
    .paginated()
    .sort()
    .select()
    .filters()
    .search();

  const teachers = await apiFeaturesInstance.mongooseQuery.populate({
    path: "courseId",
    select: "name slug createdAt",
  });

  const paginationInfo = await apiFeaturesInstance.paginationInfo;
  const all = await userModel.find({ role: systemRoles.TEACHER }).countDocuments();
  const totalPages = Math.ceil(all / paginationInfo.perPages);
  paginationInfo.totalPages = totalPages;

  if (teachers.length) {
    return res.status(200).json({ message: "Done", data: teachers, paginationInfo });
  }

  return res.status(200).json({ message: "No items yet" });
};

// _________________________userData___________________

export const userData = async (req, res, next) => {
  const { _id } = req.body;

  const user = await userModel.findById(_id);
  if (!user) {
    return next(new Error("Invalid _id", { cause: 401 }));
  }

  // Fixed: was incorrectly returning `userData` (undefined) instead of `user`
  return res.status(200).json({ message: "Done", userData: user });
};
