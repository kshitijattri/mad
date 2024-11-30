function toggleNavbar() {
    const sideNavbar = document.getElementById('sideNavbar');
    if (sideNavbar.style.display === 'block') {
        sideNavbar.style.display = 'none';
    } else {
        sideNavbar.style.display = 'block';
    }
}


  // Hide flash messages after 2 seconds
  window.addEventListener('DOMContentLoaded', (event) => {
    const flashes = document.querySelectorAll('.flashes li');
    flashes.forEach((flash) => {
      setTimeout(() => {
        flash.style.opacity = 0; // Fade the message out
        setTimeout(() => {
          flash.style.display = 'none'; // Hide the message after fade-out
        }, 500); // Wait for fade effect
      }, 2000); // Delay before hiding (2 seconds)
    });
  });