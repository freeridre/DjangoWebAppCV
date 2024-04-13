const clearIcon = document.querySelector("#clearMark");
var emailField = document.querySelector("#email");
clearIcon.addEventListener("click", function (event) {
    console.log("Button pressed");
    console.log(emailField.value);
    if (emailField.value) {
        emailField.value = "";
    }
});

let clearButtons = document.querySelectorAll('.top-info-messaging-clear-icon');
for (let i = 0; i < clearButtons.length; i++) {
    clearButtons[i].addEventListener('click', function () {
        this.parentElement.style.display = 'none';
    });
}