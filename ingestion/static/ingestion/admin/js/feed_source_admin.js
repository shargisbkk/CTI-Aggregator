(function () {
    "use strict";

    var TAXII_HEADER = "TAXII";

    function getFieldset(legendText) {
        var fieldsets = document.querySelectorAll("fieldset");
        for (var i = 0; i < fieldsets.length; i++) {
            var h2 = fieldsets[i].querySelector("h2");
            if (h2 && h2.textContent.trim() === legendText) {
                return fieldsets[i];
            }
        }
        return null;
    }

    function updateVisibility() {
        var select = document.getElementById("id_adapter_type");
        if (!select) return;
        var taxiiSection = getFieldset(TAXII_HEADER);
        if (!taxiiSection) return;
        taxiiSection.style.display = select.value === "taxii" ? "" : "none";
    }

    document.addEventListener("DOMContentLoaded", function () {
        updateVisibility();
        var select = document.getElementById("id_adapter_type");
        if (select) select.addEventListener("change", updateVisibility);
    });
}());
