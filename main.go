package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/ad3n/golang-jwt/models"
	"github.com/ad3n/golang-jwt/services"
	"github.com/gofiber/fiber/v2"
	"github.com/joho/godotenv"
)

func main() {
	godotenv.Load()
	app := fiber.New()

	app.Post("/auth/login", func(c *fiber.Ctx) error {
		user := models.User{}
		c.BodyParser(&user)
		if user.Username != "admin" || user.Password != "admin" {
			c.JSON(map[string]string{
				"message": "invalid credential",
			})

			return c.SendStatus(fiber.StatusBadRequest)
		}

		jwt := services.Jwt{}
		token, err := jwt.CreateToken(user)
		if err != nil {
			c.JSON(map[string]string{
				"message": "unable to create access token",
			})

			return c.SendStatus(fiber.StatusInternalServerError)
		}

		return c.JSON(token)
	})

	app.Get("/secured", func(c *fiber.Ctx) error {
		// This block must be part of middleware
		// @see: https://github.com/gofiber/jwt
		bearerToken := c.Get("Authorization")
		token := strings.Split(bearerToken, " ")
		if len(token) != 2 {
			c.JSON(map[string]string{
				"message": "missing token",
			})

			return c.SendStatus(fiber.StatusUnauthorized)
		}

		jwt := services.Jwt{}
		user, err := jwt.ValidateToken(token[1])
		if err != nil {
			c.JSON(map[string]string{
				"message": "invalid token",
			})

			return c.SendStatus(fiber.StatusUnauthorized)
		}
		// End block

		return c.JSON(user)
	})

	app.Post("/auth/refresh", func(c *fiber.Ctx) error {
		token := models.Token{}
		c.BodyParser(&token)

		jwt := services.Jwt{}
		user, err := jwt.ValidateRefreshToken(token)
		if err != nil {
			c.JSON(map[string]string{
				"message": "invalid token",
			})

			return c.SendStatus(fiber.StatusUnauthorized)
		}

		token, err = jwt.CreateToken(user)
		if err != nil {
			c.JSON(map[string]string{
				"message": "unable to create access token",
			})

			return c.SendStatus(fiber.StatusInternalServerError)
		}

		return c.JSON(token)
	})

	app.Listen(fmt.Sprintf(":%s", os.Getenv("APP_PORT")))
}
