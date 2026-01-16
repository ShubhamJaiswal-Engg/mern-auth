import express from "express";
import cookieParser from "cookie-parser";
import cors from "cors";
import "dotenv/config";
import connectDB from "./config/mongoose.js";
import authRouter from "./routes/authRouter.js";
import userRouter from "./routes/userRouter.js";
const app = express();

connectDB();

const port = process.env.PORT||4000;
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(cors({credentials:true}));

app.get("/",(req,res)=>{
    res.send("API Working");
});
app.use("/api/auth",authRouter);
app.use("/api/user",userRouter);
app.listen(port,()=>{
    console.log(`Server start listening at ${port}`);
})