// Light/dark theme toggle for SOC Box.
// The initial theme is applied inline in <head> (before paint) to avoid a
// flash; this just wires the toggle button and persists the choice.
(function () {
    "use strict";
    var btn = document.getElementById("theme-toggle");
    if (!btn) return;

    btn.addEventListener("click", function () {
        var current =
            document.documentElement.getAttribute("data-theme") === "light"
                ? "light"
                : "dark";
        var next = current === "light" ? "dark" : "light";
        document.documentElement.setAttribute("data-theme", next);
        try {
            localStorage.setItem("socbox-theme", next);
        } catch (e) {
            /* storage unavailable - theme still applies for this session */
        }
    });
})();
