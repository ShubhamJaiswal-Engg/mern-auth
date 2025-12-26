import express from "express";
import cookieParser from "cookie-parser";
import cors from "cors";
import "dotenv/config";
import connectDB from "./config/mongoose.js";
const app = express();

connectDB();

const port = process.env.PORT||4000;
app.use(express.json());
app.use(cookieParser());
app.use(cors({credentials:true}));

app.listen(port,()=>{
    console.log(`Server start listening at ${port}`);
})