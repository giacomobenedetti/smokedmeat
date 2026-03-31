// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

package counter

import (
	"math/rand"
	"time"
)

// adjectives for operator name generation (inspired by Docker)
var adjectives = []string{
	"admiring", "agitated", "amazing", "angry", "awesome",
	"blissful", "bold", "boring", "brave", "busy",
	"charming", "clever", "cool", "crazy", "dazzling",
	"determined", "dreamy", "eager", "ecstatic", "elastic",
	"elated", "elegant", "epic", "exciting", "fervent",
	"festive", "flamboyant", "focused", "friendly", "frosty",
	"gallant", "gifted", "goofy", "gracious", "great",
	"happy", "hardcore", "heuristic", "hopeful", "hungry",
	"infallible", "inspiring", "intelligent", "interesting",
	"jolly", "jovial", "keen", "kind", "laughing",
	"loving", "lucid", "magical", "modest", "musing",
	"mystifying", "naughty", "nervous", "nice", "nifty",
	"nostalgic", "objective", "optimistic", "peaceful", "pedantic",
	"pensive", "practical", "priceless", "quirky", "quizzical",
	"recursing", "relaxed", "reverent", "romantic", "sad",
	"serene", "sharp", "silly", "sleepy", "stoic",
	"strange", "stupefied", "suspicious", "sweet", "tender",
	"thirsty", "trusting", "unruffled", "upbeat", "vibrant",
	"vigilant", "vigorous", "wizardly", "wonderful", "xenodochial",
	"youthful", "zealous", "zen",
}

// Famous hackers, security researchers, and cryptographers
var names = []string{
	"aleph", "barnaby", "bleichenbacher", "boneh", "bratus",
	"cohen", "corman", "diffie", "dino", "draper",
	"farmer", "floyd", "goldwasser", "gutmann", "hellman",
	"kaminsky", "kernighan", "koblitz", "lamo", "levy",
	"litchfield", "linus", "matasano", "merkle", "micali",
	"mitnick", "moore", "mudge", "neumann", "ormandy",
	"perlman", "poulsen", "ptacek", "rivest", "schneier",
	"shamir", "shimomura", "solar", "stallman", "stoll",
	"torvalds", "venema", "wozniak", "zimmermann",
}

// GenerateOperatorName generates a random operator name like Docker container names.
func GenerateOperatorName() string {
	rng := rand.New(rand.NewSource(time.Now().UnixNano()))
	adj := adjectives[rng.Intn(len(adjectives))]
	name := names[rng.Intn(len(names))]
	return adj + "_" + name
}
