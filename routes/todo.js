import express from "express";

const router = express.Router();

router.get("/", (_request, response) => {
    response.status(200).json({
        success: true,
    });
});


export default router;