import {asyncHandler} from "../utils/asyncHandler.js";
import {ApiError} from "../utils/ApiError.js";
import {User} from "../models/user.model.js";
import {uploadOnCloudinary} from "../utils/cloudinary.js";
import {ApiResponse} from "../utils/ApiResponse.js";
import jwt from "jsonwebtoken";
import mongoose from "mongoose";



const generateAccessAndRefreshTokens =  async(userId) => {
    try {
        const user=await User.findById(userId);
        const accessToken = user.generateAccessToken()
        const refreshToken = user.generateRefreshToken()

        user.refreshToken=refreshToken
        await user.save({validateBeforeSave: false})
        return {refreshToken, accessToken}
    } catch (error) {
        throw new ApiError(500,"Something went wrong!")
    }
}

const registerUser = asyncHandler(async (req,res) => {
    //  res.status(200).json({
    //     message:"okay"
    // })
    const {fullName, email, username, password} = req.body
    console.log("email: ",email);

    if(fullName === ""){
        throw new ApiError(400,"FullName is required!");
    }
    if(email === ""){
        throw new ApiError(400,"Email is required!");
    }
    if(username === ""){
        throw new ApiError(400,"Username is required!");
    }
    if(password === ""){
        throw new ApiError(400,"Password is required!");
    }

    const existedUser = await User.findOne({
        $or: [{email},{username}]
    })

    if(existedUser){
        throw new ApiError(409,"User Already exists!");
    }
    // console.log(req.files);
    const avatarLocalPath= req.files?.avatar?.[0]?.path;
    const coverImageLocalPath=req.files?.coverImage?.[0]?.path;
    
    if(!avatarLocalPath){
        throw new ApiError(400,"Profile picture required!");
    }
    
    const avatar=await uploadOnCloudinary(avatarLocalPath); 
    const coverImage=await uploadOnCloudinary(coverImageLocalPath); 
    
    if(!avatar){
        throw new ApiError(400,"Profile picture required!");
    }

    const user= await User.create({
        fullName:fullName,
        email:email,
        username: username.toLowerCase(),
        password:password,
        avatar: avatar?.url || "",
        coverImage: coverImage?.url || ""
    })

    const createdUser= await User.findById(user._id).select(
        "-password -refreshToken"
    )

    if(!createdUser){
        throw new ApiError(500,"Something went wrong while registering the user!");
    }

    return res.status(201).json(
        new ApiResponse(200,createdUser, "Registration was successful!")
    )

})

const loginUser = asyncHandler( async (req,res) => {
    const {username, password, email} = req.body
    
    if(!(username || email)){
        throw new ApiError(400,"Enter username or email")
    }

    const user=await User.findOne({
        $or:[{username},{email}]
    })

    if(!user){
        throw new ApiError(404,"User does not exist!");
    }
    
    const isPasswordValid = await user.isPasswordCorrect(password)

    if(!isPasswordValid){
        throw new ApiError(401,"Invalid Password!");
    }

    const {accessToken, refreshToken} = await generateAccessAndRefreshTokens(user._id)

    const loggedInUser = await User.findById(user._id).select("-refreshToken -password")

    const options = {
        secure: true,
        httpOnly : true
    }

    return res
    .status(200)
    .cookie("accessToken",accessToken,options)
    .cookie("refreshToken",refreshToken,options)
    .json(
        new ApiResponse(
            200,
            {
                user:loggedInUser,accessToken,refreshToken
            },
            "Login Successful!"
        )
    )
})

const logoutUser = asyncHandler(async (req,res) => {
    await User.findByIdAndUpdate(
        req.user._id,
        {
            $unset:{
                refreshToken: 1
            }
        },
        {
            new: true
        }
    )

    const options = {
        secure: true,
        httpOnly : true
    }
    
    return res
    .status(200)
    .clearCookie("accessToken", options)
    .clearCookie("refreshToken", options)
    .json(
        new ApiResponse(
            200,
            {},
            "User logged out"
        )
    )
})
 
const refreshAcessToken = asyncHandler(async (req,res) =>{
    const incomingRefreshToken = req.cookies.refreshToken || req.body.refreshToken
    if (!incomingRefreshToken) {
        throw new ApiError(401, "Unauthorized Access")
    }

    try {
        const decodedToken = jwt.verify(
            incomingRefreshToken,
            process.env.REFRESH_TOKEN_SECRET,
    
        )
    
        const user = await User.findById(decodedToken?._id)
    
        if(!user){
            throw new ApiError(401,"Invalid Refresh Token")
        }
    
        if (incomingRefreshToken !== user?.refreshToken) {
            throw new ApiError(401,"Refresh Token is expired or used!")
        }
    
        const options = {
            secure: true,
            httpOnly : true
        }
        const {accessToken, newRefreshToken} = await generateAccessAndRefreshTokens(user._id)
        return res
        .status(200)
        .cookie("accessToken",accessToken,options)
        .cookie("refreshToken",newRefreshToken, options)
        .json(
            new ApiResponse(
                200,
                {accessToken,refreshToken: newRefreshToken},
                "Access Token Refreshed successfully"
            )
        )
    } catch (error) {
        throw new ApiError(401,"Invalid Refresh Token")
    }
})

const changeCurrentPassword = asyncHandler( async (req,res) => {
    const {oldPassword, newPassword,confPassword} = req.body

    if (!(newPassword === confPassword)) {
        throw new ApiError(400, "New passwords do not match!");
    }

    const user= await User.findById(req.user?._id);
    const IsPasswordCorrect = await user.isPasswordCorrect(oldPassword);

    if (!isPasswordCorrect) {
        throw new ApiError(400, "Invalid Old Password");
    }

    user.password= newPassword;
    await user.save({validateBeforeSave: false});

    return res
    .status(200)
    .json(
        new ApiResponse(200,{},"Password Modified!")
    )
})

const getCurrentUser = asyncHandler(async (req,res) => {
    return res
    .status(200)
    .json(200,req.user,"Current User Fetched!")
})

const updateAccountDetails = asyncHandler( async (req,res) => {
    const {fullName, email} = req.body
    
    if(!(fullName || email)){
        throw new ApiError(400,"FullName and email are required!")
    }

    const user = User.findByIdAndUpdate(
        req.user?._id,
        {
            $set: {
                fullName,
                email
            }
        },
        {new:true}
    ).select("-password")
    return res
    .status(200)
    .json(
        new ApiResponse(200,user,"Account details updated!")
    )
})

const updateUserAvatar = asyncHandler( async (req,res) => {
    const avatarLocalPath = req.file?.path

    if(!avatarLocalPath){
        throw new ApiError(400,"Profile picture file missing")
    }
    
    const avatar = await uploadOnCloudinary(avatarLocalPath)
    
    if(!avatar.url){
        throw new ApiError(400,"Error while uploading avatar")
    }

    const user = await User.findByIdAndUpdate(
        req.user?._id,
        {
            $set:{
                avatar: avatar.url
            }
        },
        {new: true}
    ).select("-password")

    return res
    .status(200)
    .json(
        new ApiResponse(200,user.avatar,"Profile Image updated!")
    )

})

const updateUserCover = asyncHandler( async (req,res) => {
    const coverLocalPath = req.file?.path

    if(!coverLocalPath){
        throw new ApiError(400,"Cover picture file missing")
    }
    
    const coverImage = await uploadOnCloudinary(coverLocalPath)
    
    if(!coverImage.url){
        throw new ApiError(400,"Error while uploading cover")
    }

    const user = await User.findByIdAndUpdate(
        req.user?._id,
        {
            $set:{
                coverImage: coverImage.url
            }
        },
        {new: true}
    ).select("-password")

    return res
    .status(200)
    .json(
        new ApiResponse(200,user,"Cover Image updated!")
    )

})

const getUserChannelProfile = asyncHandler ( async (req,res) => {
    const {username} = req.params

    if(!username?.trim()){
        throw new ApiError(400,"Username missing!")
    }

    const channel = await User.aggregate([
        {
            $match:{
                username: username?.toLowerCase()
            }
        },
        {
            $lookup:{
                from: "subscriptions",
                localField:"_id",
                foreignField: "channel",
                as: "subscribers" 
            }
        },
        {
            $lookup:{
                from: "subscriptions",
                localField:"_id",
                foreignField: "subscriber",
                as: "subscribedTo" 
            }
        },
        {
            $addFields:{
                subscribersCount: {
                    $size:"$subscribers"
                },
                channelsSubscribedToCount: {
                    $size:"$subscribedTo"
                },
                isSubscribed: {
                    $cond:{
                        if:{ $in: [req.user?._id, "$subscribers.subscriber"]},
                        then : true,
                        else: false

                    }
                }

            }
        },
        {
            $project:{
                fullName: 1,
                username:1,
                avatar:1,
                coverImage: 1,
                subscribersCount:1,
                channelsSubscribedToCount: 1,
                isSubscribed: 1,

            }
        }
    ])

    if(!channel?.length){
        throw new ApiError(404,"User not found!")
    }

    return res
    .status(200)
    .json(
        new ApiResponse(200,channel[0],"User channel fetched successfully")
    )

})

const getUserHistory = asyncHandler ( async (req, res) => {
     const user = await User.aggregate([
        {
            $match:{
                _id: new mongoose.Types.ObjectId(req.user._id)
            }
        },
        {
            $lookup: {
                from: "videos",
                localField: "watchHistory",
                foreignField: "_id",
                as: "watchHistory",
                pipeline:[
                    {
                        $lookup: {
                            from:"users",
                            localField: "owner",
                            foreignField:"_id",
                            as: "owner",
                            pipeline: [
                                {
                                    $project:{
                                        fullName: 1,
                                        username: 1,
                                        avatar: 1
                                    }
                                }
                            ]
                        }
                    },
                    {
                        $addFields:{
                            owner:{
                                $first: "$owner"
                            }
                        }
                    }
                ]
            }
        }
     ])

     return res
     .status(200)
     .json(
        new ApiResponse(200,user[0].watchHistory,"Watch History fetched successfully")
     )
})

export {
    registerUser,
    loginUser,
    logoutUser,
    refreshAcessToken,
    changeCurrentPassword,
    getCurrentUser,
    updateAccountDetails,
    updateUserAvatar,
    updateUserCover,
    getUserChannelProfile,
    getUserHistory
}