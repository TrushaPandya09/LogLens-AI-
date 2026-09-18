const fileInput = document.getElementById("log_file");
const fileName = document.getElementById("file-name");
const dropZone = document.querySelector(".drop-zone");

fileInput.addEventListener("change", () => {
    const selectedFile = fileInput.files[0];
    if (selectedFile) {
        fileName.textContent = `${selectedFile.name} · ${(selectedFile.size / 1024).toFixed(1)} KB`;
        dropZone.classList.add("is-selected");
    }
});
