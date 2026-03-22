package config

import (
	"log"

	"vscan-mohesr/internal/models"
)

type seedTarget struct {
	URL         string
	Name        string
	Institution string
}

func SeedUniversities() {
	var count int64
	DB.Model(&models.ScanTarget{}).Count(&count)
	if count > 0 {
		log.Printf("Database already has %d targets, skipping seed", count)
		return
	}

	// Get default org
	var org models.Organization
	DB.First(&org)

	targets := getUniversityList()

	for _, t := range targets {
		target := models.ScanTarget{
			OrganizationID: org.ID,
			URL:            t.URL,
			Name:           t.Name,
			Institution:    t.Institution,
		}
		DB.Create(&target)
	}

	log.Printf("Seeded %d university websites", len(targets))
}

func getUniversityList() []seedTarget {
	return []seedTarget{
		// ====== الجامعات الحكومية ======
		{"uobaghdad.edu.iq", "جامعة بغداد", "حكومية"},
		{"uomustansiriyah.edu.iq", "الجامعة المستنصرية", "حكومية"},
		{"uotechnology.edu.iq", "الجامعة التكنولوجية", "حكومية"},
		{"nahrainuniv.edu.iq", "جامعة النهرين", "حكومية"},
		{"uomosul.edu.iq", "جامعة الموصل", "حكومية"},
		{"uobasrah.edu.iq", "جامعة البصرة", "حكومية"},
		{"qu.edu.iq", "جامعة القادسية", "حكومية"},
		{"www.uoanbar.edu.iq", "جامعة الأنبار", "حكومية"},
		{"uokufa.edu.iq", "جامعة الكوفة", "حكومية"},
		{"uobabylon.edu.iq", "جامعة بابل", "حكومية"},
		{"uodiyala.edu.iq", "جامعة ديالى", "حكومية"},
		{"uokerbala.edu.iq", "جامعة كربلاء", "حكومية"},
		{"uowasit.edu.iq", "جامعة واسط", "حكومية"},
		{"uofallujah.edu.iq", "جامعة الفلوجة", "حكومية"},
		{"www.tu.edu.iq", "جامعة تكريت", "حكومية"},
		{"aliraqia.edu.iq", "الجامعة العراقية", "حكومية"},
		{"utq.edu.iq", "جامعة ذي قار", "حكومية"},
		{"uokirkuk.edu.iq", "جامعة كركوك", "حكومية"},
		{"uomisan.edu.iq", "جامعة ميسان", "حكومية"},
		{"mu.edu.iq", "جامعة المثنى", "حكومية"},
		{"uosamarra.edu.iq", "جامعة سامراء", "حكومية"},
		{"uoqasim.edu.iq", "جامعة القاسم الخضراء", "حكومية"},
		{"www.uos.edu.iq", "جامعة سومر", "حكومية"},
		{"uoninevah.edu.iq", "جامعة نينوى", "حكومية"},
		{"kus.edu.iq", "جامعة الكرخ للعلوم", "حكومية"},
		{"ibnsina.edu.iq", "جامعة ابن سينا للعلوم الطبية والصيدلانية", "حكومية"},
		{"buog.edu.iq", "جامعة البصرة للنفط والغاز", "حكومية"},
		{"jmu.edu.iq", "جامعة جابر بن حيان الطبية", "حكومية"},
		{"www.uohamdaniya.edu.iq", "جامعة الحمدانية", "حكومية"},
		{"uotelafer.edu.iq", "جامعة تلعفر", "حكومية"},
		{"uoitc.edu.iq", "جامعة تكنولوجيا المعلومات والاتصالات", "حكومية"},
		{"ntu.edu.iq", "الجامعة التقنية الشمالية", "حكومية"},
		{"www.stu.edu.iq", "الجامعة التقنية الجنوبية", "حكومية"},
		{"atu.edu.iq", "الجامعة التقنية الوسطى", "حكومية"},
		{"shu.edu.iq", "جامعة الشطرة", "حكومية"},

		// ====== الجامعات الأهلية ======
		{"uoturath.edu.iq", "جامعة التراث", "أهلية"},
		{"muc.edu.iq", "كلية المنصور الجامعة", "أهلية"},
		{"ruc.edu.iq", "جامعة الرافدين", "أهلية"},
		{"almamonuc.edu.iq", "جامعة المأمون", "أهلية"},
		{"sa-uc.edu.iq", "جامعة شط العرب", "أهلية"},
		{"uoa.edu.iq", "جامعة المعارف", "أهلية"},
		{"hu.edu.iq", "جامعة الحدباء", "أهلية"},
		{"baghdadcollege.edu.iq", "كلية بغداد للعلوم الاقتصادية", "أهلية"},
		{"al-yarmok.edu.iq", "كلية اليرموك الجامعة", "أهلية"},
		{"bcms.edu.iq", "كلية بغداد للعلوم الطبية", "أهلية"},
		{"www.abu.edu.iq", "جامعة اهل البيت", "أهلية"},
		{"iunajaf.edu.iq", "الجامعة الاسلامية", "أهلية"},
		{"duc.edu.iq", "جامعة دجلة", "أهلية"},
		{"alsalam.edu.iq", "كلية السلام الجامعة", "أهلية"},
		{"alkafeel.edu.iq", "جامعة الكفيل", "أهلية"},
		{"mauc.edu.iq", "جامعة مدينة العلم", "أهلية"},
		{"altoosi.edu.iq", "جامعة الشيخ الطوسي", "أهلية"},
		{"ijsu.edu.iq", "جامعة الامام جعفر الصادق", "أهلية"},
		{"iraquniversity.net", "كلية العراق الجامعة", "أهلية"},
		{"siuc.edu.iq", "كلية صدر العراق الجامعة", "أهلية"},
		{"alqalam.edu.iq", "جامعة القلم", "أهلية"},
		{"huciraq.edu.iq", "كلية الحسين الجامعة", "أهلية"},
		{"hiuc.edu.iq", "كلية الحكمة الجامعة", "أهلية"},
		{"uomus.edu.iq", "جامعة المستقبل", "أهلية"},
		{"alimamunc.edu.iq", "كلية الحضارة الجامعة", "أهلية"},
		{"hilla-unc.edu.iq", "جامعة الحلة", "أهلية"},
		{"ouc.edu.iq", "كلية اصول العلم الجامعة", "أهلية"},
		{"esraa.edu.iq", "جامعة الاسراء", "أهلية"},
		{"alsafwa.edu.iq", "جامعة الصفوة", "أهلية"},
		{"uoalkitab.edu.iq", "جامعة الكتاب", "أهلية"},
		{"alkutcollege.edu.iq", "جامعة الكوت", "أهلية"},
		{"uoalfarahidi.edu.iq", "جامعة الفراهيدي", "أهلية"},
		{"almustafauniversity.edu.iq", "جامعة المصطفى", "أهلية"},
		{"mpu.edu.iq", "كلية مزايا الجامعة", "أهلية"},
		{"alnoor.edu.iq", "جامعة النور", "أهلية"},
		{"kunoozu.edu.iq", "جامعة الكنوز", "أهلية"},
		{"alfarabiuc.edu.iq", "جامعة الفارابي", "أهلية"},
		{"albani.edu.iq", "كلية الباني الجامعة", "أهلية"},
		{"altuff.edu.iq", "كلية الطف", "أهلية"},
		{"alzahu.edu.iq", "جامعة الزهراوي", "أهلية"},
		{"alnukhba.edu.iq", "كلية النخبة الجامعة", "أهلية"},
		{"nuc.edu.iq", "جامعة النسور", "أهلية"},
		{"www.bauc14.edu.iq", "جامعة بلاد الرافدين", "أهلية"},
		{"fu.edu.iq", "جامعة الفرقدين", "أهلية"},
		{"uruk.edu.iq", "جامعة اوروك", "أهلية"},
		{"huc.edu.iq", "جامعة الهادي", "أهلية"},
		{"albayan.edu.iq", "جامعة البيان", "أهلية"},
		{"uowa.edu.iq", "جامعة وارث الانبياء", "أهلية"},
		{"alameen.edu.iq", "جامعة الامين", "أهلية"},
		{"alameed.edu.iq", "جامعة العميد", "أهلية"},
		{"au.edu.iq", "جامعة اشور", "أهلية"},
		{"uomanara.edu.iq", "جامعة المنارة", "أهلية"},
		{"alayen.edu.iq", "جامعة العين العراقية", "أهلية"},
		{"Meuc.edu.iq", "كلية الشرق الاوسط", "أهلية"},
		{"alamarhuc.edu.iq", "كلية العمارة", "أهلية"},
		{"alzahraa.edu.iq", "جامعة الزهراء للبنات", "أهلية"},
		{"gu.edu.iq", "جامعة كلكامش", "أهلية"},
		{"auib.edu.iq", "الجامعة الامريكية", "أهلية"},
		{"www.almaaqal.edu.iq", "جامعة المعقل", "أهلية"},
		{"uom.edu.iq", "جامعة المشرق", "أهلية"},
		{"ik.edu.iq", "كلية ابن خلدون", "أهلية"},
		{"uoalhuda.edu.iq", "كلية الهدى", "أهلية"},
		{"www.sawa-un.edu.iq", "جامعة ساوة", "أهلية"},
		{"alamal.edu.iq", "كلية الامل للعلوم الطبية", "أهلية"},
		{"alshaab.edu.iq", "جامعة الشعب", "أهلية"},
		{"sums.edu.iq", "جامعة السبطين", "أهلية"},
		{"alnaji-uni.edu.iq", "جامعة الناجي", "أهلية"},
		{"nibru.edu.iq", "جامعة النبراس", "أهلية"},
		{"cur.edu.iq", "جامعة قرطبة", "أهلية"},
		{"babagurguruni.edu.iq", "جامعة بابا كركر", "أهلية"},
		{"alfurqan.edu.iq", "جامعة الفرقان", "أهلية"},
		{"uosj.edu.iq", "جامعة السراج", "أهلية"},
		{"shau.edu.iq", "كلية الشرق للعلوم التقنية", "أهلية"},
		{"multaqaalnahrein.edu.iq", "كلية ملتقى النهرين", "أهلية"},
		{"snu.edu.iq", "جامعة سهل نينوى", "أهلية"},
		{"alqabas.edu.iq", "كلية القبس", "أهلية"},
	}
}
