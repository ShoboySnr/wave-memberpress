jQuery(document).ready(function ($) {
    $('input.mepr-flutterwave-testmode').each(function () {
        var integration = $(this).data('integration');

        if ($(this).is(':checked')) {
            $('#mepr-flutterwave-test-keys-' + integration).show();
            $('#mepr-flutterwave-live-keys-' + integration).hide();
        }
        else {
            $('#mepr-flutterwave-live-keys-' + integration).show();
            $('#mepr-flutterwave-test-keys-' + integration).hide();
        }
    });

    $('div#integration').on('change', 'input.mepr-flutterwave-testmode', function () {
        var integration = $(this).data('integration');
        if ($(this).is(':checked')) {
            $('#mepr-flutterwave-live-keys-' + integration).hide();
            $('#mepr-flutterwave-test-keys-' + integration).show();
        } else {
            $('#mepr-flutterwave-live-keys-' + integration).show();
            $('#mepr-flutterwave-test-keys-' + integration).hide();
        }
    });

});