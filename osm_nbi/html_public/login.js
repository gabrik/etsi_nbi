    var login_form = document.getElementById('login_form');
    var f_user = document.getElementById('f_user');
    var f_pass = document.getElementById('f_pass');
    f_user.onkeydown = function(e) {
      if (e.keyCode == 13) {
        f_pass.focus();
        return false;
      }
    }
    f_pass.onkeydown = function(e) {
      if (e.keyCode == 13) {
        login_form.submit();
        return false;
      }
    }
    f_user.focus();

