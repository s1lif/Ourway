// Можно добавить JavaScript при необходимости
document.addEventListener('DOMContentLoaded', function() {
    // Инициализация всплывающих подсказок
    const tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
    tooltipTriggerList.map(function (tooltipTriggerEl) {
        return new bootstrap.Tooltip(tooltipTriggerEl);
    });
    
    // Автоматическое закрытие алертов через 5 секунд
    const alerts = document.querySelectorAll('.alert');
    alerts.forEach(alert => {
        setTimeout(() => {
            bootstrap.Alert.getInstance(alert).close();
        }, 5000);
    });
});