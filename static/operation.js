document.addEventListener("DOMContentLoaded", () => {

    /* =====================================================
       ELEMENTS
       ===================================================== */

    const coverLibraryLink =
        document.getElementById("coverLibraryLink");

    const secretFileInput =
        document.querySelector(
            'input[name="secret_file"]'
        );

    const coverFileInput =
        document.querySelector(
            'input[name="cover_image"]'
        );

    const selectedCoverInput =
        document.querySelector(
            'input[name="cover_selected"]'
        );

    const temporarySecretInfo =
        document.getElementById(
            "temporarySecretInfo"
        );

    const libraryCoverPreview =
        document.getElementById(
            "libraryCoverPreview"
        );

    const capacityPanel =
        document.getElementById(
            "capacityPanel"
        );

    const capacityProgress =
        document.getElementById(
            "capacityProgress"
        );

    const capacityStatus =
        document.getElementById(
            "capacityStatus"
        );

    const imageCapacity =
        document.getElementById(
            "imageCapacity"
        );

    const payloadSize =
        document.getElementById(
            "payloadSize"
        );

    const capacityPercentage =
        document.getElementById(
            "capacityPercentage"
        );


    /* =====================================================
       PASSWORD SHOW / HIDE
       ===================================================== */

    const passwordInputs =
        document.querySelectorAll(
            'input[type="password"]'
        );


    passwordInputs.forEach(input => {

        if (
            input.parentElement &&
            input.parentElement.classList.contains(
                "password-wrapper"
            )
        ) {
            return;
        }


        const wrapper =
            document.createElement("div");

        wrapper.className =
            "password-wrapper";


        input.parentNode.insertBefore(
            wrapper,
            input
        );

        wrapper.appendChild(
            input
        );


        const toggle =
            document.createElement("button");

        toggle.type = "button";

        toggle.className =
            "password-toggle";

        toggle.innerHTML =
            "👁";


        toggle.addEventListener(
            "click",
            () => {

                if (
                    input.type === "password"
                ) {

                    input.type = "text";

                    toggle.innerHTML =
                        "🙈";

                } else {

                    input.type = "password";

                    toggle.innerHTML =
                        "👁";
                }

            }
        );


        wrapper.appendChild(
            toggle
        );

    });


    /* =====================================================
       PASSWORD STRENGTH
       ===================================================== */

    passwordInputs.forEach(passwordInput => {

        const parent =
            passwordInput.closest(
                ".input-group"
            );

        if (!parent) {
            return;
        }


        const strengthContainer =
            document.createElement("div");

        strengthContainer.className =
            "password-strength";


        strengthContainer.innerHTML = `

            <div class="strength-header">

                <span>Password Strength</span>

                <span class="strength-text">
                    Not entered
                </span>

            </div>

            <div class="strength-bar">

                <div class="strength-fill"></div>

            </div>

        `;


        parent.appendChild(
            strengthContainer
        );


        const strengthText =
            strengthContainer.querySelector(
                ".strength-text"
            );

        const strengthFill =
            strengthContainer.querySelector(
                ".strength-fill"
            );


        passwordInput.addEventListener(
            "input",
            () => {

                const password =
                    passwordInput.value;


                if (!password) {

                    strengthText.textContent =
                        "Not entered";

                    strengthFill.style.width =
                        "0%";

                    strengthFill.className =
                        "strength-fill";

                    return;
                }


                let score = 0;


                if (
                    password.length >= 8
                ) {
                    score++;
                }


                if (
                    /[A-Z]/.test(password)
                ) {
                    score++;
                }


                if (
                    /[a-z]/.test(password)
                ) {
                    score++;
                }


                if (
                    /[0-9]/.test(password)
                ) {
                    score++;
                }


                if (
                    /[^A-Za-z0-9]/.test(password)
                ) {
                    score++;
                }


                if (score <= 1) {

                    strengthText.textContent =
                        "Very Weak";

                    strengthFill.style.width =
                        "20%";

                    strengthFill.className =
                        "strength-fill very-weak";

                } else if (score === 2) {

                    strengthText.textContent =
                        "Weak";

                    strengthFill.style.width =
                        "40%";

                    strengthFill.className =
                        "strength-fill weak";

                } else if (score === 3) {

                    strengthText.textContent =
                        "Medium";

                    strengthFill.style.width =
                        "60%";

                    strengthFill.className =
                        "strength-fill medium";

                } else if (score === 4) {

                    strengthText.textContent =
                        "Strong";

                    strengthFill.style.width =
                        "80%";

                    strengthFill.className =
                        "strength-fill strong";

                } else {

                    strengthText.textContent =
                        "Very Strong";

                    strengthFill.style.width =
                        "100%";

                    strengthFill.className =
                        "strength-fill very-strong";
                }

            }
        );

    });


    /* =====================================================
       FILE INFORMATION
       ===================================================== */

    const fileInputs =
        document.querySelectorAll(
            'input[type="file"]'
        );


    fileInputs.forEach(input => {

        const info =
            document.createElement("div");

        info.className =
            "file-selected-info";


        info.style.display =
            "none";


        input.parentNode.insertBefore(
            info,
            input.nextSibling
        );


        input.addEventListener(
            "change",
            () => {

                if (!input.files.length) {

                    info.style.display =
                        "none";

                    info.innerHTML =
                        "";

                    return;
                }


                const file =
                    input.files[0];


                info.style.display =
                    "block";


                info.innerHTML = `

                    📄
                    <strong>
                        ${escapeHtml(file.name)}
                    </strong>

                    <span>
                        (${formatFileSize(file.size)})
                    </span>

                `;


                /* =========================================
                   SECRET FILE
                   ========================================= */

                if (
                    input === secretFileInput
                ) {

                    if (
                        temporarySecretInfo
                    ) {

                        temporarySecretInfo.style.display =
                            "none";
                    }
                    secretPreparationPromise = prepareSecretFile(file);

                    const removeButton = document.getElementById("removeSecretBtn");
                    if (removeButton) {
                        removeButton.style.display = "inline-block";
            }
                }


                /* =========================================
                   COVER IMAGE
                   ========================================= */

                if (
                    input === coverFileInput
                ) {

                    createImagePreview(
                        file,
                        info
                    );


                    /*
                     * Device cover overrides the
                     * library cover.
                     */

                    if (
                        selectedCoverInput
                    ) {

                        selectedCoverInput.value =
                            "";
                    }


                    if (
                        libraryCoverPreview
                    ) {

                        libraryCoverPreview.style.display =
                            "none";
                    }


                    /*
                     * Clear the library selection
                     * from the Flask session.
                     */

                    clearServerSelectedCover();

                    coverPreparationPromise = prepareCoverFile(file);

                }


                /* =========================================
                   CAPACITY
                   ========================================= */

                if (
                    input === secretFileInput ||
                    input === coverFileInput
                ) {

                    setTimeout(
                        () => {
                            checkCapacity();
                        },
                        50
                    );

                }

            }
        );

    });


    /* =====================================================
       ESCAPE HTML
       ===================================================== */

    function escapeHtml(value) {

        const div =
            document.createElement("div");

        div.textContent =
            value;

        return div.innerHTML;
    }


    /* =====================================================
       IMAGE PREVIEW
       ===================================================== */

    function createImagePreview(
        file,
        info
    ) {

        if (
            !file.type.startsWith("image/")
        ) {

            info.innerHTML += `
                <div>
                    ❌ Invalid image file.
                </div>
            `;

            return;
        }


        const reader =
            new FileReader();


        reader.onload =
            event => {

                const oldPreview =
                    info.querySelector(
                        ".cover-preview"
                    );


                if (oldPreview) {
                    oldPreview.remove();
                }


                const image =
                    document.createElement(
                        "img"
                    );


                image.src =
                    event.target.result;


                image.className =
                    "cover-preview";


                image.alt =
                    "Selected Cover";


                info.appendChild(
                    image
                );

            };


        reader.readAsDataURL(
            file
        );

    }


    /* =====================================================
       FILE SIZE
       ===================================================== */

    function formatFileSize(
        bytes
    ) {

        if (
            bytes === 0
        ) {
            return "0 Bytes";
        }


        const units = [
            "Bytes",
            "KB",
            "MB",
            "GB"
        ];


        const index =
            Math.floor(
                Math.log(bytes) /
                Math.log(1024)
            );


        return (
            parseFloat(
                (
                    bytes /
                    Math.pow(
                        1024,
                        index
                    )
                ).toFixed(2)
            )
            +
            " "
            +
            units[index]
        );

    }


    /* =====================================================
       CLEAR SERVER LIBRARY COVER
       ===================================================== */

    async function clearServerSelectedCover() {

        try {

            await fetch(
                "/clear-cover",
                {
                    method: "POST"
                }
            );

        } catch (error) {

            console.error(
                "Unable to clear server cover:",
                error
            );

        }

    }



    /* =====================================================
       TEMPORARY FILE PREPARATION
       ===================================================== */

    let secretPreparationPromise = Promise.resolve();
    let coverPreparationPromise = Promise.resolve();

    async function prepareSecretFile(file) {
        const formData = new FormData();
        formData.append("secret_file", file);

        try {
            const response = await fetch("/prepare-encryption", {
                method: "POST",
                body: formData
            });

            const result = await response.json();
            console.log("Capacity response:", result);

            if (!response.ok || !result.success) {
                throw new Error(
                    result.message || "Unable to save secret file."
                );
            }

            if (temporarySecretInfo) {
                temporarySecretInfo.style.display = "block";
                temporarySecretInfo.classList.add("visible");
                temporarySecretInfo.innerHTML =
                    `🔐 Secret file saved: <strong>${escapeHtml(file.name)}</strong>`;
            }

        } catch (error) {
            console.error("Secret preparation error:", error);
            alert(error.message);
        }
    }

    async function prepareCoverFile(file) {
        const formData = new FormData();
        formData.append("cover_image", file);

        try {
            const response = await fetch("/prepare-cover", {
                method: "POST",
                body: formData
            });

            const result = await response.json();

            if (!response.ok || !result.success) {
                throw new Error(
                    result.message || "Unable to save cover image."
                );
            }

            console.log("Temporary cover saved:", result.filename);

        } catch (error) {
            console.error("Cover preparation error:", error);
            alert(error.message);
        }
    }


const removeSecretBtn = document.getElementById("removeSecretBtn");

if (removeSecretBtn) {
    const secretInput = document.getElementById("secretFile");
    const secretInfo = document.getElementById("temporarySecretInfo");

    // Show the button when a saved secret already exists.
    if (document.body.dataset.tempSecret === "true") {
        removeSecretBtn.style.display = "inline-block";
    }

    removeSecretBtn.addEventListener("click", async function () {
        if (!confirm("Are you sure you want to remove the secret file?")) {
            return;
        }

        try {
            // Wait for a newly selected file to finish saving.
            await secretPreparationPromise;

            const response = await fetch("/clear-secret", {
                method: "POST",
                headers: {
                    "X-Requested-With": "XMLHttpRequest"
                }
            });

            const result = await response.json();

            if (!response.ok || !result.success) {
                alert(result.message || "Unable to remove the secret file.");
                return;
            }

            if (secretInput) {
                secretInput.value = "";
            }

            if (secretInfo) {
                secretInfo.style.display = "none";
                secretInfo.classList.remove("visible");
            }

            window.location.reload();
        } catch (error) {
            console.error("Remove secret error:", error);
            alert("Could not remove the secret file. Please try again.");
        }
    });
}

    /* =====================================================
       CAPACITY CHECK
       ===================================================== */

    async function checkCapacity() {

        if (
            !capacityPanel ||
            !secretFileInput
        ) {
            return;
        }


        const hasTemporarySecret =
            document.body.dataset.tempSecret ===
            "true";


        const hasBrowserSecret =
            secretFileInput.files.length >
            0;


        /* ================================================
           SECRET CHECK
           ================================================ */

        if (
            !hasBrowserSecret &&
            !hasTemporarySecret
        ) {

            resetCapacityCheck();

            return;
        }


        /* ================================================
           COVER CHECK
           ================================================ */

        const hasCoverFile =
            coverFileInput &&
            coverFileInput.files.length >
            0;


        const hasSelectedCover =
            selectedCoverInput &&
            selectedCoverInput.value;


        if (
            !hasCoverFile &&
            !hasSelectedCover
        ) {

            resetCapacityCheck();

            return;
        }


        /* ================================================
           COVER TYPE VALIDATION
           ================================================ */

        if (
            hasCoverFile
        ) {

            const coverFile =
                coverFileInput.files[0];


            if (
                !coverFile.type.startsWith(
                    "image/"
                )
            ) {

                showCapacityError(
                    "Please select a valid image cover."
                );

                return;
            }

        }


        /* ================================================
           CHECKING MESSAGE
           ================================================ */

        capacityStatus.textContent =
            "⏳ Checking image capacity...";


        capacityStatus.className =
            "capacity-status checking";


        capacityProgress.style.width =
            "0%";


        capacityPercentage.textContent =
            "Checking...";


        /* ================================================
           FORM DATA
           ================================================ */

        const formData =
            new FormData();


        if (
            hasBrowserSecret
        ) {

            formData.append(
                "secret_file",
                secretFileInput.files[0]
            );

        }


        if (
            hasCoverFile
        ) {

            formData.append(
                "cover_image",
                coverFileInput.files[0]
            );

        }


        try {

            const response =
                await fetch(
                    "/check-capacity",
                    {
                        method: "POST",
                        body: formData
                    }
                );


            const result =
                await response.json();


            if (
                !response.ok ||
                !result.success
            ) {

                throw new Error(
                    result.message ||
                    "Capacity check failed."
                );

            }


            /* ============================================
                CAPACITY DETAILS
                ============================================ */

            document.getElementById("capacityStatusValue")
            .textContent =
                result.status
                ? result.status.toUpperCase()
                : "--";


            document.getElementById("secretFileSize")
            .textContent =
            formatFileSize(
            result.secret_size || 0
            );


            document.getElementById("coverDimensions")
            .textContent =
            `${result.width} × ${result.height} pixels`;


            document.getElementById("availableCapacity")
             .textContent =
            formatFileSize(
            result.capacity_bytes || 0
            );


            document.getElementById("estimatedPayload")
            .textContent =
            formatFileSize(
            result.payload_bytes || 0
            );


            document.getElementById("requiredBits")
            .textContent =
            `${result.required_bytes || 0} bytes / ` +
            `${result.required_bits || 0} bits`;


            document.getElementById("remainingCapacity")
            .textContent =
            formatFileSize(
            result.remaining_bytes || 0
             );


            /* ============================================
                PERCENTAGE
                 ============================================ */

            const percentage =
              Math.min(
                result.percentage || 0,
                100
                );


            capacityProgress.style.width =
             `${percentage}%`;


            capacityPercentage.textContent =
            `${(result.percentage || 0).toFixed(2)}%`;


            /* ============================================
            STATUS MESSAGE
            ============================================ */

            capacityStatus.textContent =
         result.message || "";


            capacityStatus.className =
            `capacity-status ${result.status}`;


            /* ============================================
            PROGRESS CLASS
            ============================================ */

            capacityProgress.className =
            "capacity-progress " +
            (result.status || "");

        }


        catch (error) {

            console.error(
                "Capacity check error:",
                error
            );


            showCapacityError(
                error.message
            );

        }

    }


    /* =====================================================
       RESET CAPACITY
       ===================================================== */

    function resetCapacityCheck() {

        if (!capacityPanel) {
            return;
        }


        if (imageCapacity) {

            imageCapacity.textContent =
                "--";
        }


        if (payloadSize) {

            payloadSize.textContent =
                "--";
        }


        if (capacityProgress) {

            capacityProgress.style.width =
                "0%";

            capacityProgress.className =
                "capacity-progress";
        }


        if (capacityPercentage) {

            capacityPercentage.textContent =
                "0%";
        }


        if (capacityStatus) {

            capacityStatus.textContent =
                "Select a secret file and cover image to check capacity.";

            capacityStatus.className =
                "capacity-status";
        }

    }


    /* =====================================================
       CAPACITY ERROR
       ===================================================== */

    function showCapacityError(
        message
    ) {

        if (capacityStatus) {

            capacityStatus.textContent =
                "❌ " + message;

            capacityStatus.className =
                "capacity-status danger";
        }


        if (capacityProgress) {

            capacityProgress.style.width =
                "100%";

            capacityProgress.className =
                "capacity-progress danger";
        }


        if (capacityPercentage) {

            capacityPercentage.textContent =
                "Error";
        }

    }


    /* =====================================================
       COVER LIBRARY NAVIGATION
       ===================================================== */

    if (
        coverLibraryLink &&
        secretFileInput
    ) {

        coverLibraryLink.addEventListener(
            "click",
            async event => {

                /*
                 * If a temporary secret already exists,
                 * simply go to the library.
                 */

                const hasTemporarySecret =
                    document.body.dataset.tempSecret ===
                    "true";


                if (
                    !secretFileInput.files.length
                ) {

                    return;

                }


                /*
                 * A new browser secret exists.
                 *
                 * Save it temporarily before opening
                 * the cover library.
                 */

                event.preventDefault();


                const secretFile =
                    secretFileInput.files[0];


                const formData =
                    new FormData();


                formData.append(
                    "secret_file",
                    secretFile
                );


                try {

                    coverLibraryLink.textContent =
                        "⏳ Preparing...";


                    coverLibraryLink.style.pointerEvents =
                        "none";


                    const response =
                        await fetch(
                            "/prepare-encryption",
                            {
                                method: "POST",
                                body: formData
                            }
                        );


                    const result =
                        await response.json();


                    if (
                        !response.ok ||
                        !result.success
                    ) {

                        throw new Error(
                            result.message ||
                            "Unable to prepare the secret file."
                        );

                    }


                    window.location.href =
                        "/cover-library";

                }


                catch (error) {

                    console.error(
                        "Cover library error:",
                        error
                    );


                    alert(
                        error.message
                    );


                    coverLibraryLink.textContent =
                        "🖼 Choose From Cover Library";


                    coverLibraryLink.style.pointerEvents =
                        "auto";

                }

            }
        );

    }


    /* =====================================================
       FORM SUBMIT
       ===================================================== */

    const forms =
        document.querySelectorAll(
            'form[action="/encrypt"]'
        );


    forms.forEach(form => {

        form.addEventListener(
            "submit",
            () => {

                const submitButton =
                    form.querySelector(
                        'button[type="submit"]'
                    );


                if (!submitButton) {
                    return;
                }


                submitButton.disabled =
                    true;


                submitButton.textContent =
                    "⏳ Encrypting...";

            }
        );

    });


    /* =====================================================
       INITIAL CAPACITY CHECK
       ===================================================== */

    const initialHasTemporarySecret =
        document.body.dataset.tempSecret ===
        "true";


    const initialHasSelectedCover =
        selectedCoverInput &&
        selectedCoverInput.value;


    if (
        initialHasTemporarySecret &&
        initialHasSelectedCover
    ) {

        setTimeout(
            () => {
                checkCapacity();
            },
            200
        );

    } else {

        resetCapacityCheck();

    }


    /* =====================================================
       PAGE SHOW / BFCACHE PROTECTION
       ===================================================== */

    window.addEventListener(
        "pageshow",
        event => {

            if (
                event.persisted
            ) {

                window.location.reload();

            }

        }
    );

});
