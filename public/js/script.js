document.addEventListener("DOMContentLoaded", () => {
    const allBtns = document.querySelectorAll(".searchBtn");
    const searchBar = document.querySelector(".searchBar");
    const searchInput = document.getElementById("searchInput");
    const searchClose = document.getElementById("searchClose");

    for (let i = 0; i < allBtns.length; i++) {
        allBtns[i].addEventListener('click', () => {
            searchBar.style.visibility = "visible";
            searchBar.classList.add("open");
            allBtns[i].setAttribute('aria-expanded', 'true'); // Update aria-expanded for clicked button
            searchInput.focus(); 
        });
    }

    searchClose.addEventListener('click', () => {
        searchBar.style.visibility = "hidden"; // Fix the typo here
        searchBar.classList.remove("open"); // Remove the open class if it's supposed to be hidden
        allBtns.forEach(btn => btn.setAttribute('aria-expanded', 'false')); // Update aria-expanded for all buttons
    });
});
