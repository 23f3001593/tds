const { chromium } = require("playwright");

(async () => {
  const seeds = Array.from({ length: 10 }, (_, i) => 16 + i); // 16..25
  const browser = await chromium.launch();
  const page = await browser.newPage();

  let grandTotal = 0;

  for (const seed of seeds) {
    const url = `https://sanand0.github.io/tdsdata/js_table/?seed=${seed}`;
    await page.goto(url, { waitUntil: "networkidle" });

    // Grab every table cell's text on the page
    const cellTexts = await page.$$eval("table td, table th", (cells) =>
      cells.map((c) => c.textContent.trim())
    );

    let seedSum = 0;
    for (const text of cellTexts) {
      const num = parseFloat(text.replace(/,/g, ""));
      if (!isNaN(num)) seedSum += num;
    }

    console.log(`Seed ${seed}: sum = ${seedSum}`);
    grandTotal += seedSum;
  }

  console.log(`TOTAL SUM ACROSS ALL SEEDS: ${grandTotal}`);
  await browser.close();
})();