package web

import (
	routes "packiffer/src/web/routes"

	"github.com/gofiber/fiber/v2"
)

func run() {
	app := fiber.New()
	routes.Setup(app)
	app.Listen(":3000")
}
