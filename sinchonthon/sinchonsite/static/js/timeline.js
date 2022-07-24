const open = () => {
	document.querySelector('.timeline-open');
};
const close = () => {
	document.querySelector('.close-modal');
};
const modal = document.querySelector('timeline-modal');

function init() {
	open.addEventListener('click', function () {
		modal.classList.remove('hidden');
	});
	close.addEventListener('click', function () {
		modal.classList.add('hidden');
	});
}

init();
// document.querySelector('.timeline-open').addEventListener('click', open);
// document.querySelector('.timeline-close').addEventListener('click', close);
// document.querySelector('.bg').addEventListener('click', close);
