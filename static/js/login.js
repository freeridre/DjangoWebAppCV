
const showPassword = document.querySelector('#showPassword');
const passwordField = document.querySelector('#password');

showPassword.addEventListener('click', function(event){
    const type = passwordField.getAttribute('type') === 'password' ? 'text': 'password';
    passwordField.setAttribute('type', type);
    this.classList.toggle('fa-eye-slash');
    
});

const clearIcon = document.querySelector("#clearMark");
var usernameField = document.querySelector("#username");
clearIcon.addEventListener("click", function(event){
    console.log("Button pressed");
    console.log(usernameField.value);
    if(usernameField.value)
    {
        usernameField.value = "";
    }
});

const clearPassword = document.querySelector("#clearMark_2");
var passField = document.querySelector("#password");
clearPassword.addEventListener("click", function (event) {
    console.log("Button pressed");
    console.log(passField.value);
    if (passField.value) {
        passField.value = "";
    }
});

let video = document.querySelector('.bg-video');
video.controls = false;
video.addEventListener("Contextmenu", function (e) {
    e.preventDefault();
}, false);

let clearButtons = document.querySelectorAll('.top-info-messaging-clear-icon');
for (let i = 0; i < clearButtons.length; i++) {
    clearButtons[i].addEventListener('click', function () {
        let parentElement = this.parentElement; // .errorlist
        let grandparentElement = parentElement.parentElement; // .top-info-messaging

        // Remove both .errorlist and .top-info-messaging
        grandparentElement.style.display = 'none';
    });
}