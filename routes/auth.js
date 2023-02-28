import express from "express";
import jwt from "jsonwebtoken";
import argon2 from "argon2";
import prisma from "../db/index.js";



const router = express.Router();

// /auth/login
router.post("/login", async (request, response) => {
  //Handle login

  // We want to make sure we're able to find this user
  try {
    const foundUser = await prisma.user.findFirst({
      where: {
        username: request.body.username,
      },
    });

    // Once we found the user, we want to make sure that both the hashed password and the password the client sent us match.
    // argon will handle this for us with its method verify().
    if (foundUser) {
      try {
        const verifyPassword = await argon2.verify(
          foundUser.password,
          request.body.password
        );

        // If these passwords do match, we want to create a JWT for our client
        if (verifyPassword) {
          // They're going to use this token to access any protected routes that we have.
          // method Sign() => passing in data that we want to embed into the JWT. It takes two args: payload and secretOrPrivateKey.
          const token = jwt.sign(
            // This payload will be encrypted into the token
            { username: foundUser.username, id: foundUser.id },
            // The secret key used to sign our token That way once it get encryped, you'll need this key to decrypt it.
            "thisIsASecretKey"
          );

          // We send back status of 200 and JSON with success: true and the token.
          response.status(200).json({
            success: true,
            token
            // short hand of writing => token: token 
          });

          // If the passwords don't match send back status 401
        } else {
          response.status(401).json({
            success: false,
            message: "Wrong username or password"
          });
        }
        // For everything else, just let them know something went wrong.
      } catch (err) {
        response.status(500).json({
          success: false,
          message: "Something went wrong",
        });
      }
    }
    // If no user is found
  } catch (err) {
    response.status(500).json({
      success: false,
      message: "Something went wrong",
    });
  }

});


// /auth/signup
router.post("/signup", async (request, response) => {
  //handle signup

  try {
    //whatever username the client has sent to us we are checking by that username
    const foundUser = await prisma.user.findFirst({
      where: {
        username: request.body.username,
      },
    });
    // If the user does exist, we want to respond with 401 letting them know that the user exists.
    if (foundUser) {
      response.status(401).json({
        success: false,
        message: "User already exists",
      });

    } else {
      // If they don't exist then we want to go through the process of acutally signing up our user
      try {
        // Hashes the password with argon2
        const hashedPassword = await argon2.hash(request.body.password);
        // Then create that user inside of our database.
        const newUser = await prisma.user.create({
          // This database is going to hold thier username and password(hashed password)
          data: {
            username: request.body.username,
            password: hashedPassword,
          }
        });

        // If the new user was created and we do get something back from this variable(newUser), then we want to let the user/client know:
        // user was created success is set to true, message: "User successfully created"
        if (newUser) {
          response.status(201).json({
            success: true,
            message: "User successfully created",
          });
          // If it doesn't give us any data back, let the user/client know user was not created something happened. 
        } else {
          response.status(500).json({
            success: false,
            message: "User was not created. Something happened",
          });
        }
      } catch (err) {
        response.status(500).json({
          success: false,
          message: "User was not created. Something happened",
        });
      }
    }
    // When we are searching for the user and something happens we want to let client know something happened.
  } catch (err) {
    response.status(500).json({
      success: false,
      message: "Something went wrong",
    });
  }

});

export default router;
