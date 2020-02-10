console.log('WORKS!')

window.onload = function(e){
    $("#messageForm").submit(function(e) {
        e.preventDefault();
    });

var socket = io.connect(location.protocol + '//' + document.domain + ':' + location.port);

socket.on('connect', () => {
    button = document.getElementById('sendMessageButton');
    button.onclick = () => {
        console.log('clicked');
        var message = document.getElementById("message").value;
        const username = document.getElementById('username').value;
        const pathArray = window.location.pathname.split('/');
        const channel = pathArray[3];
        localStorage.setItem('current-channel', channel)
        socket.emit('broadcast message', {'message': message, 'username': username, 'channel': channel});
    };
});

socket.on('show message', data => {
    const li = document.createElement('li');
    li.innerHTML = `${data.username}: <b>${data.message}</b><br><i>at ${data.time}</i><hr>`;
    document.querySelector("#messages").append(li);
})

};