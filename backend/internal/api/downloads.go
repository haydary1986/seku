package api

import (
	"github.com/gofiber/fiber/v2"
	"gorm.io/gorm"

	"seku/internal/config"
	"seku/internal/models"
)

// agentBinaries maps a public platform key to the baked binary path + the
// filename the browser should save it as.
var agentBinaries = map[string]struct{ path, name string }{
	"windows":     {"/app/agents/seku-agent-windows-amd64.exe", "seku-agent.exe"},
	"macos-arm64": {"/app/agents/seku-agent-macos-arm64", "seku-agent-macos-arm64"},
	"macos-intel": {"/app/agents/seku-agent-macos-intel", "seku-agent-macos-intel"},
	"linux":       {"/app/agents/seku-agent-linux-amd64", "seku-agent-linux-amd64"},
}

// GetDownloadStats returns per-platform and total agent download counts (public).
func GetDownloadStats(c *fiber.Ctx) error {
	var stats []models.DownloadStat
	config.DB.Find(&stats)
	total := int64(0)
	byPlatform := map[string]int64{}
	for _, s := range stats {
		total += s.Count
		byPlatform[s.Platform] = s.Count
	}
	return c.JSON(fiber.Map{"total": total, "by_platform": byPlatform})
}

// DownloadAgent serves an agent binary and increments its download counter (public).
func DownloadAgent(c *fiber.Ctx) error {
	platform := c.Params("platform")
	bin, ok := agentBinaries[platform]
	if !ok {
		return c.Status(404).JSON(fiber.Map{"error": "unknown platform"})
	}

	// increment the counter (upsert then atomic +1)
	var stat models.DownloadStat
	config.DB.Where(models.DownloadStat{Platform: platform}).FirstOrCreate(&stat)
	config.DB.Model(&models.DownloadStat{}).Where("platform = ?", platform).
		UpdateColumn("count", gorm.Expr("count + 1"))

	return c.Download(bin.path, bin.name)
}
