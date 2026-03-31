(function () {
    "use strict";

    function toggleSections() {
        var select = document.getElementById("id_adapter_type");
        if (!select) return;

        var selected = select.value;  // "json", "csv", "text", "misp", "taxii"

        // Each adapter fieldset has classes "adapter-section adapter-{type}"
        // Django admin wraps fieldsets in <fieldset class="...">
        var sections = document.querySelectorAll("fieldset.adapter-section");
        sections.forEach(function (fs) {
            if (fs.classList.contains("adapter-" + selected)) {
                fs.style.display = "";
            } else {
                fs.style.display = "none";
            }
        });
    }

    document.addEventListener("DOMContentLoaded", function () {
        var select = document.getElementById("id_adapter_type");
        if (select) {
            select.addEventListener("change", toggleSections);
            toggleSections();  // run on page load for edit forms
        }
    });
})();
