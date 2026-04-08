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

    // Show GET-only fields (since_param, initial_days) or POST-only field (request_body).
    function updateMethodFields() {
        var methodSelect = document.getElementById("id_method");
        if (!methodSelect) return;
        var isPost = methodSelect.value === "POST";

        var requestBodyRow = getRow("id_request_body");
        var sinceParamRow  = getRow("id_since_param");
        var initialDaysRow = getRow("id_initial_days");

        if (requestBodyRow) requestBodyRow.style.display = isPost ? ""     : "none";
        if (sinceParamRow)  sinceParamRow.style.display  = isPost ? "none" : "";
        if (initialDaysRow) initialDaysRow.style.display  = isPost ? "none" : "";
    }

    function updateVisibility() {
        var adapterSelect = document.getElementById("id_adapter_type");
        if (!adapterSelect) return;
        var val = adapterSelect.value;

        var restApiSection     = getFieldset("REST API");
        var csvSection         = getFieldset("CSV / TSV");
        var taxiiSection       = getFieldset("TAXII");
        var advancedSection    = getFieldset("Advanced Config");

        if (restApiSection)  restApiSection.style.display  = val === "json"  ? "" : "none";
        if (csvSection)      csvSection.style.display      = val === "csv"   ? "" : "none";
        if (taxiiSection)    taxiiSection.style.display    = val === "taxii" ? "" : "none";
        // Advanced Config is useful for REST API and CSV, not for text/misp/taxii.
        if (advancedSection) advancedSection.style.display = (val === "json" || val === "csv") ? "" : "none";

        updateMethodFields();
    }

    document.addEventListener("DOMContentLoaded", function () {
        updateVisibility();

        var adapterSelect = document.getElementById("id_adapter_type");
        if (adapterSelect) adapterSelect.addEventListener("change", updateVisibility);

        var methodSelect = document.getElementById("id_method");
        if (methodSelect) methodSelect.addEventListener("change", updateMethodFields);
    });
}());
