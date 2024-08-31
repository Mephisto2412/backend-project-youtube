// require('dotenv').config({path: './env'})
import dotenv from "dotenv";
import connectDB from "./db/index.js";
import { app } from "./app.js";

dotenv.config({
    path: './.env'
})

connectDB()
.then(()=>{
    app.listen(process.env.PORT || 8000, () => {
        console.log(`Server is running at port: ${process.env.PORT}`);
    })
})
.catch((error)=>{
    console.log("MONGODB CONNECTION FAILED! :",error);
})

// ;(async () => {
//     try{
//         await mongoose.connect(`${process.env.MONGODB.URI}/${DB_NAME}`);

//     }  catch(error){
//         console.error("ERROR: ",error);
//         throw error;
//     }
// })()