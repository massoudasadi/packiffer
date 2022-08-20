package auth

import (
	auth_controller "packiffer/src/web/controllers/auth"

	"github.com/gofiber/fiber/v2"
)

func Setup(app *fiber.App) {
	app.Post("/auth/login", auth_controller.Login)
}
