// +build linux windows darwin freebsd netbsd openbsd

package main

import (
	"os"

	"fyne.io/fyne"
	"fyne.io/fyne/app"
	"fyne.io/fyne/canvas"
	"fyne.io/fyne/layout"
	"fyne.io/fyne/theme"
	"fyne.io/fyne/widget"
	"github.com/wcharczuk/go-chart"
)

func (p *packiffer) handleui() {
	a := app.New()
	a.Settings().SetTheme(theme.LightTheme())
	w := a.NewWindow("Packiffer")
	w.Resize(fyne.NewSize(800, 600))

	image := canvas.NewImageFromFile("/home/massoud/packiffer/packiffer.png")
	image.Resize(fyne.NewSize(600, 200))
	image.SetMinSize(fyne.NewSize(600, 200))

	logo := fyne.NewContainerWithLayout(layout.NewHBoxLayout(),
		layout.NewSpacer(), image, layout.NewSpacer())

	hello := widget.NewLabel("Cross-Platform Packet Sniffer")

	// message := fyne.NewContainerWithLayout(layout.NewHBoxLayout(),
	// 	layout.NewSpacer(), hello, layout.NewSpacer())

	interfaceTextBox := widget.NewSelect(getInterfaceNames(), func(value string) {

	})
	interfaceTextBox.PlaceHolder = "Select interface ..."

	filterTextBox := widget.NewEntry()
	filterTextBox.SetPlaceHolder("Enter Filter ...")

	button := widget.NewButton("Start Sniffing ...", func() {
		hello.SetText("Sniffing")
	})

	spaceContainer := fyne.NewContainerWithLayout(layout.NewGridWrapLayout(fyne.NewSize(30, 1)),
		widget.NewLabel(""))

	// combo := widget.NewSelect([]string{"libpcap", "pfring", "afpacket"}, func(value string) {

	// })
	// combo.PlaceHolder = "Select Engine ..."

	verticalspace := fyne.NewContainerWithLayout(layout.NewVBoxLayout(), layout.NewSpacer(), widget.NewLabel(" "), layout.NewSpacer())

	container := fyne.NewContainerWithLayout(layout.NewHBoxLayout(),
		verticalspace,
		interfaceTextBox,
		spaceContainer,
		filterTextBox,
		spaceContainer,
		//combo,
		spaceContainer,
		button)

	tabcontainer := fyne.NewContainerWithLayout(layout.NewVBoxLayout(),
		verticalspace,
		container)

	tabs := widget.NewTabContainer(
		widget.NewTabItem("Sniff", tabcontainer),
		widget.NewTabItem("Transform", widget.NewLabel("Transform!")),
		widget.NewTabItem("Inspect", widget.NewLabel("Inspect!")),
		widget.NewTabItem("inject", widget.NewLabel("inject!")),
		widget.NewTabItem("help", widget.NewLabel("help!")))

	w.SetContent(fyne.NewContainerWithLayout(
		layout.NewVBoxLayout(),
		logo,
		// message,
		widget.NewLabel(""),
		tabs,
		widget.NewLabel("")))
	w.ShowAndRun()
}

func (p *packiffer) displaychart() {
	pie := chart.PieChart{
		Width:  512,
		Height: 512,
		Values: []chart.Value{
			{Value: float64(packetCount), Label: "ALL"},
			{Value: float64(udpCount), Label: "UDP"},
			{Value: float64(ipCount), Label: "IP"},
			{Value: float64(tcpCount), Label: "TCP"},
			{Value: float64(arpCount), Label: "ARP"},
			{Value: float64(ethCount), Label: "Ethernet"},
			{Value: float64(otherCount), Label: "Other"},
			{Value: float64(httpCount), Label: "HTTP"},
		},
	}
	chartOutput, _ := os.Create("chartOutput.png")
	defer chartOutput.Close()
	pie.Render(chart.PNG, chartOutput)
}
