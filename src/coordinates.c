/* Where a country is, for the fourteen characters an identifier ends with.
 *
 * Copyright 2026 Jean-Jacques Brucker (u4sRyUhEbNU5OwyLEjfSwaXAe_42.17-002.76) <jjbrucker@foopgp.org>
 * Copyright 2026 Mnêmê (u5001777236237.945e_43.30_005.38 claude-opus-5) <mneme@foopgp.org>
 *
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * GENERATED from bl-pgpid's BL_PGPID_COORDINATES by tools/gen-coordinates.sh.
 * Two hundred and thirty-one entries are not worth retyping: a transcription
 * error here would mint identifiers that look right and are not, for one
 * country, silently.
 *
 * The shape is 'e' then latitude and longitude, each preceded by '_' for
 * positive and '-' for negative — a sign that survives a file name and a URL,
 * which '+' does not.
 */
#include "pgpid.h"

#include <ctype.h>
#include <string.h>

static const struct {
    char code[4];
    char coord[15];
} COUNTRIES[] = {
    { "ABW", "e_12.52-069.98" },  /* Aruba */
    { "AFG", "e_33.84_066.00" },  /* افغانستان */
    { "AGO", "e-12.29_017.54" },  /* Angola */
    { "AIA", "e_18.22-063.06" },  /* Anguilla */
    { "ALA", "e_60.21_019.95" },  /* Åland */
    { "ALB", "e_41.14_020.05" },  /* Shqipëria */
    { "AND", "e_42.54_001.56" },  /* Andorra */
    { "ARE", "e_23.91_054.30" },  /* الإمارات العربية المتحدة */
    { "ARG", "e-35.38-065.18" },  /* Argentina */
    { "ARM", "e_40.29_044.93" },  /* Հայաստան */
    { "ASM", "e-14.30-170.72" },  /* Amerika Sāmoa */
    { "ATA", "e-80.51_019.92" },  /* Antarctica */
    { "ATF", "e-49.25_069.23" },  /* Terres australes et antarctiques françaises */
    { "ATG", "e_17.28-061.79" },  /* Antigua and Barbuda */
    { "AUS", "e-25.73_134.49" },  /* Australia */
    { "AUT", "e_47.59_014.13" },  /* Österreich */
    { "AZE", "e_40.29_047.55" },  /* Azərbaycan */
    { "BDI", "e-03.36_029.88" },  /* Uburundi/Burundi */
    { "BEL", "e_50.64_004.64" },  /* België/Belgique/Belgien */
    { "BEN", "e_09.64_002.33" },  /* Bénin */
    { "BFA", "e_12.27-001.75" },  /* Burkina Faso */
    { "BGD", "e_23.87_090.24" },  /* বাংলাদেশ */
    { "BGR", "e_42.77_025.22" },  /* България */
    { "BHR", "e_26.04_050.54" },  /* البحرين */
    { "BHS", "e_24.29-076.63" },  /* Bahamas */
    { "BIH", "e_44.17_017.77" },  /* Bosna i Hercegovina/Босна и Херцеговина */
    { "BLM", "e_17.90-062.84" },  /* Saint-Barthélemy */
    { "BLR", "e_53.53_028.03" },  /* Беларусь */
    { "BLZ", "e_17.20-088.71" },  /* Belize */
    { "BMU", "e_32.31-064.75" },  /* Bermuda */
    { "BOL", "e-16.71-064.69" },  /* Bolivia/Buliwya/Wuliwya */
    { "BRA", "e-10.79-053.10" },  /* Brasil */
    { "BRB", "e_13.18-059.56" },  /* Barbados */
    { "BRN", "e_04.52_114.72" },  /* Brunei Darussalam */
    { "BTN", "e_27.41_090.40" },  /* འབྲུག་ཡུལ */
    { "BWA", "e-22.18_023.80" },  /* Botswana */
    { "CAF", "e_06.57_020.47" },  /* Ködörösêse tî Bêafrîka/République centrafricaine */
    { "CAN", "e_61.36-098.31" },  /* Canada */
    { "CHE", "e_46.80_008.21" },  /* Schweiz/Suisse/Svizzera/Svizra */
    { "CHL", "e-37.73-071.38" },  /* Chile */
    { "CHN", "e_36.56_103.82" },  /* 中国 */
    { "CIV", "e_07.63-005.57" },  /* Côte d'Ivoire */
    { "CMR", "e_05.69_012.74" },  /* Cameroun/Cameroon */
    { "COD", "e-02.88_023.64" },  /* République démocratique du Congo */
    { "COG", "e-00.84_015.22" },  /* République du Congo */
    { "COK", "e-21.22-159.79" },  /* Kūki ʻĀirani/Cook Islands */
    { "COL", "e_03.91-073.08" },  /* Colombia */
    { "COM", "e-11.88_043.68" },  /* جزر القمر/Komori/Comores */
    { "CPV", "e_15.96-023.96" },  /* Cabo Verde */
    { "CRI", "e_09.98-084.19" },  /* Costa Rica */
    { "CUB", "e_21.62-079.02" },  /* Cuba */
    { "CUW", "e_12.20-068.97" },  /* Curaçao */
    { "CYM", "e_19.43-080.91" },  /* Cayman Islands */
    { "CYP", "e_34.92_033.01" },  /* Κύπρος/Kıbrıs */
    { "CZE", "e_49.73_015.31" },  /* Česko */
    { "DEU", "e_51.11_010.39" },  /* Deutschland */
    { "DJI", "e_11.75_042.56" },  /* جيبوتي/Djibouti */
    { "DMA", "e_15.44-061.36" },  /* Dominica */
    { "DNK", "e_55.98_010.03" },  /* Danmark */
    { "DOM", "e_18.89-070.51" },  /* República Dominicana */
    { "DZA", "e_28.16_002.62" },  /* الجزائر */
    { "ECU", "e-01.42-078.75" },  /* Ecuador */
    { "EGY", "e_26.50_029.86" },  /* مصر */
    { "ERI", "e_15.36_038.85" },  /* ኤርትራ/إرتريا/Ertra */
    { "ESP", "e_40.24-003.65" },  /* España */
    { "EST", "e_58.67_025.54" },  /* Eesti */
    { "ETH", "e_08.62_039.60" },  /* ኢትዮጵያ */
    { "FIN", "e_64.50_026.27" },  /* Suomi/Finland */
    { "FJI", "e-17.43_165.45" },  /* Viti/Fiji */
    { "FRA", "e_42.17-002.76" },  /* France */
    { "FRO", "e_62.05-006.88" },  /* Føroyar */
    { "FSM", "e_07.45_153.24" },  /* Federated States of Micronesia */
    { "GAB", "e-00.59_011.79" },  /* Gabon */
    { "GBR", "e_54.12-002.87" },  /* United Kingdom */
    { "GEO", "e_42.17_043.51" },  /* საქართველო */
    { "GGY", "e_49.47-002.57" },  /* Guernsey */
    { "GHA", "e_07.95-001.22" },  /* Ghana */
    { "GIN", "e_10.44-010.94" },  /* Guinée */
    { "GMB", "e_13.45-015.40" },  /* The Gambia */
    { "GNB", "e_12.05-014.95" },  /* Guiné-Bissau */
    { "GNQ", "e_01.71_010.34" },  /* Guinea Ecuatorial/Guinée équatoriale/Guiné Equatorial */
    { "GRC", "e_39.07_022.96" },  /* Ελλάδα */
    { "GRD", "e_12.12-061.68" },  /* Grenada */
    { "GRL", "e_74.71-041.34" },  /* Kalaallit Nunaat */
    { "GTM", "e_15.69-090.36" },  /* Guatemala */
    { "GUM", "e_13.44_144.77" },  /* Guåhån */
    { "GUY", "e_04.79-058.98" },  /* Guyana */
    { "HKG", "e_22.40_114.11" },  /* 香港/Hong Kong */
    { "HMD", "e-53.09_073.52" },  /* Heard Island and McDonald Islands */
    { "HND", "e_14.83-086.62" },  /* Honduras */
    { "HRV", "e_45.08_016.40" },  /* Hrvatska */
    { "HTI", "e_18.94-072.69" },  /* Ayiti/Haïti */
    { "HUN", "e_47.16_019.40" },  /* Magyarország */
    { "IDN", "e-02.22_117.24" },  /* Indonesia */
    { "IMN", "e_54.22-004.54" },  /* Isle of Man/Ellan Vannin */
    { "IND", "e_22.89_079.61" },  /* भारत/India */
    { "IRL", "e_53.18-008.14" },  /* Éire/Ireland */
    { "IRN", "e_32.58_054.27" },  /* ایران */
    { "IRQ", "e_33.04_043.74" },  /* العراق/کوردستان */
    { "ISL", "e_65.00-018.57" },  /* Ísland */
    { "ISR", "e_31.46_035.00" },  /* ישראל/إسرائيل */
    { "ITA", "e_42.80_012.07" },  /* Italia */
    { "JAM", "e_18.16-077.31" },  /* Jamaica */
    { "JEY", "e_49.22-002.13" },  /* Jersey */
    { "JOR", "e_31.25_036.77" },  /* الأردن */
    { "JPN", "e_37.59_138.03" },  /* 日本 */
    { "KAZ", "e_48.16_067.29" },  /* Қазақстан/Казахстан */
    { "KEN", "e_00.60_037.80" },  /* Kenya */
    { "KGZ", "e_41.46_074.54" },  /* Кыргызстан/Кыргыз Республикасы */
    { "KHM", "e_12.72_104.91" },  /* កម្ពុជា */
    { "KIR", "e_00.86-045.61" },  /* Kiribati */
    { "KNA", "e_17.26-062.69" },  /* Saint Kitts and Nevis */
    { "KOR", "e_36.39_127.84" },  /* 대한민국 */
    { "KWT", "e_29.33_047.59" },  /* الكويت */
    { "LAO", "e_18.50_103.74" },  /* ປະເທດລາວ */
    { "LBN", "e_33.92_035.88" },  /* لبنان */
    { "LBR", "e_06.45-009.32" },  /* Liberia */
    { "LBY", "e_27.03_018.01" },  /* ليبيا */
    { "LCA", "e_13.89-060.97" },  /* Saint Lucia */
    { "LIE", "e_47.14_009.54" },  /* Liechtenstein */
    { "LKA", "e_07.61_080.70" },  /* ශ්‍රී ලංකා/இலங்கை */
    { "LSO", "e-29.58_028.23" },  /* Lesotho */
    { "LTU", "e_55.33_023.89" },  /* Lietuva */
    { "LUX", "e_49.77_006.07" },  /* Lëtzebuerg/Luxembourg/Luxemburg */
    { "LVA", "e_56.85_024.91" },  /* Latvija */
    { "MAC", "e_22.22_113.51" },  /* 澳門/Macau */
    { "MAF", "e_18.09-063.06" },  /* Saint-Martin */
    { "MAR", "e_29.84-008.46" },  /* المغرب/ⵍⵎⵖⵔⵉⴱ */
    { "MCO", "e_43.75_007.41" },  /* Monaco */
    { "MDA", "e_47.19_028.46" },  /* Moldova */
    { "MDG", "e-19.37_046.70" },  /* Madagasikara/Madagascar */
    { "MDV", "e_03.73_073.46" },  /* ދިވެހިރާއްޖެ */
    { "MEX", "e_23.95-102.52" },  /* México */
    { "MHL", "e_07.00_170.34" },  /* Aolepān Aorōkin M̧ajeļ/Marshall Islands */
    { "MKD", "e_41.60_021.68" },  /* Северна Македонија */
    { "MLI", "e_17.35-003.54" },  /* Mali */
    { "MLT", "e_35.92_014.41" },  /* Malta */
    { "MMR", "e_21.19_096.49" },  /* မြန်မာ */
    { "MNE", "e_42.79_019.24" },  /* Crna Gora/Црна Гора */
    { "MNG", "e_46.83_103.05" },  /* Монгол улс */
    { "MNP", "e_15.83_145.62" },  /* Sankattan Siha Na Islas Mariånas */
    { "MOZ", "e-17.27_035.53" },  /* Moçambique */
    { "MRT", "e_20.26-010.35" },  /* موريتانيا */
    { "MSR", "e_16.74-062.19" },  /* Montserrat */
    { "MUS", "e-20.28_057.57" },  /* Maurice/Mauritius/Moris */
    { "MWI", "e-13.22_034.29" },  /* Malaŵi */
    { "MYS", "e_03.79_109.70" },  /* Malaysia */
    { "NAM", "e-22.13_017.21" },  /* Namibia */
    { "NCL", "e-21.30_165.68" },  /* Nouvelle-Calédonie */
    { "NER", "e_17.42_009.39" },  /* Niger */
    { "NFK", "e-29.05_167.95" },  /* Norfolk Island */
    { "NGA", "e_09.59_008.09" },  /* Nigeria */
    { "NIC", "e_12.85-085.03" },  /* Nicaragua */
    { "NIU", "e-19.05-169.87" },  /* Niuē/Niue */
    { "NLD", "e_52.10_005.28" },  /* Nederland */
    { "NOR", "e_68.75_015.35" },  /* Norge/Noreg */
    { "NPL", "e_28.25_083.92" },  /* नेपाल */
    { "NRU", "e-00.52_166.93" },  /* Naoero/Nauru */
    { "NZL", "e-41.81_171.48" },  /* Aotearoa/New Zealand */
    { "OMN", "e_20.61_056.09" },  /* عمان */
    { "PAK", "e_29.95_069.34" },  /* پاکستان */
    { "PAN", "e_08.52-080.12" },  /* Panamá */
    { "PCN", "e-24.37-128.32" },  /* Pitcairn Islands */
    { "PER", "e-09.15-074.38" },  /* Perú */
    { "PHL", "e_11.78_122.88" },  /* Pilipinas/Philippines */
    { "PLW", "e_07.29_134.41" },  /* Belau/Palau */
    { "PNG", "e-06.46_145.21" },  /* Papua Niugini/Papua New Guinea */
    { "POL", "e_52.13_019.39" },  /* Polska */
    { "PRI", "e_18.23-066.47" },  /* Puerto Rico */
    { "PRK", "e_40.15_127.19" },  /* 조선민주주의인민공화국 */
    { "PRT", "e_39.60-008.50" },  /* Portugal */
    { "PRY", "e-23.23-058.40" },  /* Paraguay/Tetã Paraguái */
    { "PSE", "e_31.92_035.20" },  /* فلسطين */
    { "PYF", "e-14.72-144.90" },  /* Polynésie française/Pōrīnetia Farāni */
    { "QAT", "e_25.31_051.18" },  /* قطر */
    { "ROU", "e_45.85_024.97" },  /* România */
    { "RUS", "e_61.98_096.69" },  /* Россия */
    { "RWA", "e-01.99_029.92" },  /* Rwanda */
    { "SAU", "e_24.12_044.54" },  /* المملكة العربية السعودية */
    { "SDN", "e_15.99_029.94" },  /* السودان */
    { "SEN", "e_14.37-014.47" },  /* Sénégal */
    { "SGP", "e_01.36_103.82" },  /* Singapore/新加坡/சிங்கப்பூர்/Singapura */
    { "SGS", "e-54.46-036.43" },  /* South Georgia and South Sandwich Islands */
    { "SHN", "e-12.40-009.55" },  /* Saint Helena */
    { "SLB", "e-08.92_159.63" },  /* Solomon Islands */
    { "SLE", "e_08.56-011.79" },  /* Sierra Leone */
    { "SLV", "e_13.74-088.87" },  /* El Salvador */
    { "SMR", "e_43.94_012.46" },  /* San Marino */
    { "SOM", "e_04.75_045.71" },  /* Soomaaliya/الصومال */
    { "SPM", "e_46.92-056.30" },  /* Saint-Pierre-et-Miquelon */
    { "SRB", "e_44.22_020.79" },  /* Србија */
    { "SSD", "e_07.31_030.25" },  /* South Sudan */
    { "STP", "e_00.44_006.72" },  /* São Tomé e Príncipe */
    { "SUR", "e_04.13-055.91" },  /* Suriname */
    { "SVK", "e_48.71_019.48" },  /* Slovensko */
    { "SVN", "e_46.12_014.80" },  /* Slovenija */
    { "SWE", "e_62.78_016.75" },  /* Sverige */
    { "SWZ", "e-26.56_031.48" },  /* Eswatini */
    { "SXM", "e_18.05-063.06" },  /* Sint Maarten */
    { "SYC", "e-04.66_055.48" },  /* Sesel/Seychelles */
    { "SYR", "e_35.03_038.51" },  /* سوريا */
    { "TCA", "e_21.83-071.97" },  /* Turks and Caicos Islands */
    { "TCD", "e_15.33_018.64" },  /* Tchad/تشاد */
    { "TGO", "e_08.53_000.96" },  /* Togo */
    { "THA", "e_15.12_101.00" },  /* ประเทศไทย */
    { "TJK", "e_38.53_071.01" },  /* Тоҷикистон */
    { "TKM", "e_39.12_059.37" },  /* Türkmenistan */
    { "TLS", "e-08.83_125.84" },  /* Timor-Leste/Timor Lorosa'e */
    { "TON", "e-20.43-174.81" },  /* Tonga */
    { "TTO", "e_10.46-061.27" },  /* Trinidad and Tobago */
    { "TUN", "e_34.12_009.55" },  /* تونس */
    { "TUR", "e_39.06_035.17" },  /* Türkiye */
    { "TZA", "e-06.28_034.81" },  /* Tanzania */
    { "UGA", "e_01.27_032.37" },  /* Uganda */
    { "UKR", "e_49.00_031.38" },  /* Україна */
    { "URY", "e-32.80-056.02" },  /* Uruguay */
    { "USA", "e_45.68-112.46" },  /* United States */
    { "UZB", "e_41.76_063.14" },  /* Oʻzbekiston */
    { "VAT", "e_41.90_012.43" },  /* Vaticano/Vaticanum */
    { "VCT", "e_13.22-061.20" },  /* Saint Vincent and the Grenadines */
    { "VEN", "e_07.12-066.18" },  /* Venezuela */
    { "VGB", "e_18.53-064.47" },  /* British Virgin Islands */
    { "VIR", "e_17.96-064.80" },  /* United States Virgin Islands */
    { "VNM", "e_16.65_106.30" },  /* Việt Nam */
    { "VUT", "e-16.23_167.69" },  /* Vanuatu */
    { "WLF", "e-13.89-177.35" },  /* Wallis-et-Futuna */
    { "WSM", "e-13.75-172.16" },  /* Sāmoa */
    { "YEM", "e_15.91_047.59" },  /* اليمن */
    { "ZAF", "e-29.00_025.08" },  /* South Africa/Suid-Afrika/iNingizimu Afrika */
    { "ZMB", "e-13.46_027.77" },  /* Zambia */
    { "ZWE", "e-19.00_029.85" },  /* Zimbabwe */
};

/* The fourteen characters for a three-letter country code, or NULL.
 * Refused rather than guessed: an identifier ending in the wrong place is
 * indistinguishable from a right one. */
const char *pgpid_country_coordinates(const char *code)
{
    if (!code || strlen(code) != 3)
        return NULL;
    char upper[4] = {
        (char)toupper((unsigned char)code[0]),
        (char)toupper((unsigned char)code[1]),
        (char)toupper((unsigned char)code[2]),
        0,
    };
    size_t lo = 0, hi = sizeof COUNTRIES / sizeof *COUNTRIES;
    while (lo < hi) {
        size_t mid = (lo + hi) / 2;
        int c = strcmp(upper, COUNTRIES[mid].code);
        if (!c)
            return COUNTRIES[mid].coord;
        if (c < 0)
            hi = mid;
        else
            lo = mid + 1;
    }
    return NULL;
}
