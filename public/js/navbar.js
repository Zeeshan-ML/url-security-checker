document.addEventListener("DOMContentLoaded", () => {
  const hamburger = document.getElementById("hamburger");
  const navLinks = document.getElementById("nav-links");

  // Toggle nav menu when hamburger is clicked
  hamburger.addEventListener("click", () => {
    navLinks.classList.toggle("show");
  });

  // Close nav menu when any nav link is clicked
  const navItems = navLinks.querySelectorAll("a");
  navItems.forEach(link => {
    link.addEventListener("click", () => {
      navLinks.classList.remove("show");
    });
  });
});
