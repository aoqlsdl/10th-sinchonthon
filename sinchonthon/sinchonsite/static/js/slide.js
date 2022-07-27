var slides = document.querySelector('.slides');
var slideImg = document.querySelectorAll('.slides li');
let currentIdx = 0;
// const prev = document.querySelector('.prev'); //이전 버튼
// const next = document.querySelector('.next'); //다음 버튼
const slideWidth = 3700; //한개의 슬라이드 넓이
const slideMargin = 100; //슬라이드간의 margin 값

//전체 슬라이드 컨테이너 넓이 설정
slides.style.width = (slideWidth + slideMargin) * slideCount + 'px';

function moveSlide(num) {
	slides.style.left = -num * 400 + 'px';
	currentIdx = num;
}

prev.addEventListener('click', function () {
	if (currentIdx !== 0) moveSlide(currentIdx - 1);
});

next.addEventListener('click', function () {
	if (currentIdx !== slideCount - 1) {
		moveSlide(currentIdx + 1);
	}
});
