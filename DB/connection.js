import mongoose from "mongoose";

import dotenv from 'dotenv';
dotenv.config();

const dbUrlCloud = process.env.DB_URL_CLOUD;


export const connectionDB = async () => {
  return await mongoose
    .connect(dbUrlCloud)
    .then(() => {
      console.log("connection DB success");
    })
    .catch(() => {
      console.log("connection DB faild");
    });
};
