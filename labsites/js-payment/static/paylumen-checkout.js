// A fictional payment-gateway-like SDK (shape similar to common hosted checkouts).
window.PayLumen = function (opts) {
  return {
    open: function () {
      var c = document.getElementById("checkout");
      c.innerHTML =
        '<h2>Pay ' + opts.amount + ' ' + opts.currency + ' to ' + opts.name + '</h2>' +
        '<form id="card" action="/pay" method="post">' +
        '<input name="cardnumber" autocomplete="cc-number" placeholder="Card number">' +
        '<input name="exp" autocomplete="cc-exp" placeholder="MM/YY">' +
        '<input name="cvc" autocomplete="cc-csc" placeholder="CVC">' +
        '<button>Pay now</button></form>' +
        '<p>Or scan to pay with UPI:</p><img src="/static/upi-qr.png" width="200" height="200" alt="UPI QR">';
    }
  };
};
