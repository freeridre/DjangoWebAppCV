const clearPassword1 = document.querySelector("#clearMark_2");
var passField1 = document.querySelector("#new_password1");
clearPassword1.addEventListener("click", function (event) {
    console.log("Button pressed");
    console.log(passField1.value);
    if (passField1.value) {
        passField1.value = "";
    }
});

const showPassword1 = document.querySelector('#showPassword1');
const passwordField1 = document.querySelector('#new_password1');

showPassword1.addEventListener('click', function (event) {
    const type = passwordField1.getAttribute('type') === 'password' ? 'text' : 'password';
    passwordField1.setAttribute('type', type);
    this.classList.toggle('fa-eye-slash');

});

const clearConfPassword = document.querySelector("#clearMark_3");
var passField2 = document.querySelector("#new_password2");
clearConfPassword.addEventListener("click", function (event) {
    console.log("Button pressed 2");
    console.log(passField2.value);
    if (passField2.value) {
        passField2.value = "";
    }
});

const showPassword2 = document.querySelector('#showPassword2');
const passwordField2 = document.querySelector('#new_password2');

showPassword2.addEventListener('click', function (event) {
    const type = passwordField2.getAttribute('type') === 'password' ? 'text' : 'password';
    passwordField2.setAttribute('type', type);
    this.classList.toggle('fa-eye-slash');

});

let clearButtons = document.querySelectorAll('.top-info-messaging-clear-icon');
for (let i = 0; i < clearButtons.length; i++) {
    clearButtons[i].addEventListener('click', function () {
        this.parentElement.style.display = 'none';
    });
}