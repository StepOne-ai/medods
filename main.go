package main

import (
	"github.com/StepOne-ai/medods/database"
	"github.com/StepOne-ai/medods/handler"
	"github.com/StepOne-ai/medods/middleware"
	"github.com/gin-gonic/gin"
)

func main() {
	r := gin.Default()

	database.InitDB()
	defer database.CloseDB()

	r.POST("/login", handler.LoginHandler)
	r.POST("/refresh", middleware.AuthMiddleware(), handler.RefreshHandler)
	r.POST("/logout", middleware.AuthMiddleware(), handler.LogoutHandler)
	r.GET("/me", middleware.AuthMiddleware(), handler.MeHandler)

	r.Run(":8080")
}