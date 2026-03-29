/*
    This script adds all of the functionality to collapsable button icons for the html
    pages. It uses the font awesome library and assigns different icons depending on
    if the target of the collapse selector is currently shown or hidden. 
*/

document.addEventListener('DOMContentLoaded', function(){
    // This line creates an array of elements that all contain the custom selector
    // data-bs-toggle="collapse" in all html documents that extends Base.html
    const collapseButtons = document.querySelectorAll('[data-bs-toggle="collapse"]');

    // Loop through all collapse buttons and create three constants: a var for icon,
    // the collapsable targetid, and the collapsable target itself
    collapseButtons.forEach(button =>{
        const icon = button.querySelector('i');
        const targetId = button.getAttribute('data-bs-target');
        const target = document.querySelector(targetId);

        // Adds a listener to the target to tell the icon to change its icon when the
        // target becomes shown
        target.addEventListener('show.bs.collapse', () => {
            icon.classList.remove('fa-chevron-down');
            icon.classList.add('fa-chevron-up');
        });

        // Adds a listener to the target to tell the icon to change its icon when the
        // target becomes hidden
        target.addEventListener('hide.bs.collapse', () => {
            icon.classList.remove('fa-chevron-up');
            icon.classList.add('fa-chevron-down');
        });

    });
});