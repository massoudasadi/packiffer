package routes

import (
	auth_routes "packiffer/src/web/routes/auth"

	"github.com/gofiber/fiber/v2"

	base_controller "packiffer/src/web/controllers"
)

func Setup(app *fiber.App) {
	app.Get("/", base_controller.Status)
	auth_routes.Setup(app)
}
