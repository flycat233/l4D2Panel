function downloadfile(filename) {
    window.location.href = '/download/' + filename;
}

$(document).ready(function () {
    $('#uploadform').on('submit', function (event) {
        event.preventDefault();
        let formData = new FormData(this);

        // 重置进度条
        $('#progressbar').css('width', '0%').attr('aria-valuenow', 0);
        $('#progresstext').text('0%');

        $.ajax({
            url: '/upload',
            type: 'POST',
            data: formData,
            processData: false,
            contentType: false,
            xhr: function () {
                let xhr = new window.XMLHttpRequest();
                xhr.upload.addEventListener('progress', function (e) {
                    if (e.lengthComputable) {
                        let percent = Math.round((e.loaded / e.total) * 100);
                        $('#progressbar').css('width', percent + '%')
                            .attr('aria-valuenow', percent);
                        $('#progresstext').text(percent + '%');
                    }
                }, false);
                return xhr;
            },
            success: function (response) {
                $('#progressbar').css('width', '100%');
                setTimeout(() => window.location.reload(), 500);
            },
            error: function (xhr, status, error) {
                $('#progresstext').text('Upload failed');
            }
        });
    });
});
