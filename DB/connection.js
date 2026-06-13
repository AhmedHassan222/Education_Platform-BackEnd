import mongoose from "mongoose";

import dotenv from 'dotenv';
dotenv.config();

export const connectionDB = async () => {
  const dbUrlCloud = process.env.DB_URL_CLOUD;
  
  if (!dbUrlCloud) {
    console.log("connection DB faild: DB_URL_CLOUD is not defined in environment variables.");
    return;
  }

  return await mongoose
    .connect(dbUrlCloud)
    .then(() => {
      console.log("connection DB success");
    })
    .catch((err) => {
      console.log("connection DB faild: ", err.message);
    });
};
