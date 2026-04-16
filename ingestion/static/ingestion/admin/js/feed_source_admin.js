(function () {
    "use strict";

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

    function getRow(fieldId) {
        var el = document.getElementById(fieldId);
        return el ? el.closest(".form-row") : null;
    }

    // Show request_body only for POST; hide otherwise.
    function updateMethodFields() {
        var methodSelect = document.getElementById("id_method");
        if (!methodSelect) return;
        var isPost = methodSelect.value === "POST";
        var requestBodyRow = getRow("id_request_body");
        if (requestBodyRow) requestBodyRow.style.display = isPost ? "" : "none";
    }

    // Auto-expand a collapsed Django fieldset if any of its inputs have a value.
    function autoExpandIfPopulated(fieldset) {
        if (!fieldset) return;
        var inputs = fieldset.querySelectorAll("input[type='text'], textarea, select");
        var hasValue = false;
        for (var i = 0; i < inputs.length; i++) {
            var v = inputs[i].value;
            if (v && v.trim() !== "" && v !== "GET" && v !== ",") {
                hasValue = true;
                break;
            }
        }
        if (hasValue) {
            // Django admin collapse.js uses class "collapse" + removes it when expanded.
            // Simulate a click on the toggle link to let Django's own JS handle the state.
            var toggle = fieldset.querySelector("a.collapse-toggle");
            if (toggle && fieldset.classList.contains("collapsed")) {
                toggle.click();
            }
        }
    }

    function updateVisibility() {
        var adapterSelect = document.getElementById("id_adapter_type");
        if (!adapterSelect) return;
        var val = adapterSelect.value;

        var restApiSection  = getFieldset("REST API");
        var csvSection      = getFieldset("CSV / TSV");
        var taxiiSection    = getFieldset("TAXII");
        var advancedSection = getFieldset("Advanced Config");

        if (restApiSection)  restApiSection.style.display  = val === "json"  ? "" : "none";
        if (csvSection)      csvSection.style.display      = val === "csv"   ? "" : "none";
        if (taxiiSection)    taxiiSection.style.display    = val === "taxii" ? "" : "none";
        // Advanced Config is for JSON sources only (CSV uses the CSV/TSV section).
        if (advancedSection) advancedSection.style.display = val === "json" ? "" : "none";

        updateMethodFields();
    }

    document.addEventListener("DOMContentLoaded", function () {
        updateVisibility();

        // Auto-expand Advanced Config on existing records that already have values set.
        autoExpandIfPopulated(getFieldset("Advanced Config"));

        var adapterSelect = document.getElementById("id_adapter_type");
        if (adapterSelect) adapterSelect.addEventListener("change", updateVisibility);

        var methodSelect = document.getElementById("id_method");
        if (methodSelect) methodSelect.addEventListener("change", updateMethodFields);
    });
}());
