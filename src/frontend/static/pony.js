(function () {
  "use strict";

  const NS = "http://www.w3.org/2000/svg";
  const VB_W = 250;
  const VB_H = 200;

  const HEAD_PATH =
    "M34.5 30.5 L54.3 52.8 L59.7 60.7 L59.7 61.5 L58.8 61.8 L54.4 60 L51.9 64.4 L50.3 69.1 L49.9 72.7 L54.3 70.9 L55.5 78.4 L55 82.7 L51.6 88.1 L52.4 90 L54.4 91.5 L58.7 92.1 L65 85 L67.5 83.8 L69.4 83.8 L71.2 85.3 L71.8 86.6 L70.7 88.5 L64.5 88.5 L59.7 92.5 L62.6 94.1 L67.5 95.2 L74.3 92.4 L86.4 89.7 L90.1 87.3 L90.2 87.9 L88.2 93.4 L84.5 101.1 L77.8 110.9 L84.3 111.2 L92.9 110 L99.2 108 L105.2 104.4 L108.4 101.2 L110.7 97.4 L111.5 93.9 L111.8 86.6 L113 87.7 L114.9 92.1 L116.9 88.5 L117.4 86.1 L117.3 80.5 L115.7 76.7 L113.8 74.1 L116.4 73.8 L121.9 74.9 L119.8 70.2 L114.4 61.8 L112.9 62.3 L109.3 62 L101.8 55.7 L108.1 54.1 L108.1 52.8 L106.8 50.8 L102.3 46.9 L97.4 44.5 L91.9 43 L89.7 38 L85.8 34.5 L80 32.5 L76 32.3 L75.6 32.8 L78.5 37.4 L78.5 38.7 L73.1 38 L65.2 39.8 L59.7 40.2 L60.7 43.1 L66 51 L65.5 51.3 L53.9 44ZM77.8 56.7 L77.1 61 L76 64.5 L73.1 67 L67 67.8 L67 67 L70.7 62.3 L74.3 58.9Z";

  const PART_NAMES = [
    "body",
    "neck",
    "head",
    "tail",
    "mane",
    "legFL1",
    "legFL2",
    "legFR1",
    "legFR2",
    "legBL1",
    "legBL2",
    "legBR1",
    "legBR2",
  ];

  const PIVOTS = {
    body: [150, 122],
    neck: [110, 114],
    head: [95, 100.7],
    mane: [112.5, 83.6],
    tail: [210, 104],
    legFL1: [100, 124],
    legFL2: [100, 164],
    legFR1: [112, 124],
    legFR2: [112, 164],
    legBL1: [190, 120],
    legBL2: [194, 162],
    legBR1: [178, 120],
    legBR2: [182, 162],
  };

  const BODY = [
    [86, 114],
    [94, 102],
    [122, 92],
    [136, 95],
    [150, 98],
    [166, 98],
    [182, 94],
    [196, 89],
    [208, 92],
    [216, 102],
    [219, 116],
    [214, 132],
    [204, 142],
    [188, 140],
    [170, 146],
    [148, 148],
    [124, 147],
    [106, 143],
    [94, 134],
    [87, 124],
  ];
  const NECK = [
    [87.7, 106.1],
    [108.1, 86.9],
    [114.9, 90.9],
    [121.3, 93.6],
    [128, 99],
    [128, 106],
    [106, 120],
    [96.7, 124.1],
    [94.3, 118.9],
    [90.6, 114.3],
    [83.2, 113.8],
  ];
  const MANE = [
    [110.1, 82.6],
    [121, 72.1],
    [124.2, 73.2],
    [123.1, 81.2],
    [115.3, 83.7],
    [113.6, 85.4],
    [124, 75.4],
    [127.1, 76.6],
    [126.3, 84.4],
    [118.9, 86.4],
    [117.2, 88],
    [126.6, 79.2],
    [129.7, 80.5],
    [129.3, 87.6],
    [122.2, 89.3],
    [120.7, 90.7],
    [128.7, 83.6],
    [131.7, 84.9],
    [134.1, 93.2],
    [125.6, 92.2],
    [124.4, 93.4],
    [130.3, 88.6],
    [135.1, 91.9],
    [142.9, 103],
    [131.3, 97.5],
    [130, 98],
    [128, 106],
    [103.6, 90.3],
  ];
  const TAIL = [
    [204, 98],
    [216, 93],
    [228, 95],
    [238, 104],
    [244, 118],
    [245, 134],
    [241, 152],
    [237, 138],
    [233, 148],
    [228, 166],
    [226, 148],
    [221, 136],
    [216, 150],
    [214, 132],
    [208, 116],
  ];

  const LIGHT = "#FFFFFF";
  const DARK = "#0A5FC8";
  const FACETS = {
    body: [
      [
        [
          [94, 102],
          [122, 92],
          [150, 98],
          [182, 94],
          [196, 89],
          [150, 112],
          [110, 112],
        ],
        LIGHT,
        0.12,
      ],
      [
        [
          [196, 89],
          [208, 92],
          [216, 102],
          [219, 116],
          [200, 112],
        ],
        LIGHT,
        0.18,
      ],
      [
        [
          [106, 143],
          [140, 132],
          [188, 140],
          [170, 146],
          [148, 148],
          [124, 147],
        ],
        DARK,
        0.22,
      ],
    ],
    mane: [
      [
        [
          [118.4, 76.4],
          [123.1, 81.2],
          [115.3, 84.1],
        ],
        DARK,
        0.22,
      ],
      [
        [
          [121.6, 79.6],
          [126.3, 84.4],
          [118.8, 86.9],
        ],
        DARK,
        0.22,
      ],
      [
        [
          [124.6, 83],
          [129.3, 87.6],
          [122.2, 89.7],
        ],
        DARK,
        0.22,
      ],
      [
        [
          [127.1, 86.8],
          [134.1, 93.2],
          [125.6, 92.6],
        ],
        DARK,
        0.22,
      ],
      [
        [
          [129.4, 91],
          [142.9, 103],
          [131.6, 98.1],
        ],
        DARK,
        0.22,
      ],
    ],
    neck: [
      [
        [
          [90.6, 114.3],
          [94.3, 118.9],
          [96.7, 124.1],
          [105.5, 117.4],
          [100.1, 110.5],
        ],
        DARK,
        0.18,
      ],
    ],
    tail: [
      [
        [
          [214, 132],
          [221, 136],
          [226, 148],
          [228, 166],
          [233, 148],
          [222, 120],
        ],
        DARK,
        0.2,
      ],
    ],
  };

  const LEGS = {
    F: {
      upper: [
        [-9, -10],
        [9, -10],
        [10, 10],
        [6, 22],
        [5, 32],
        [6, 40],
        [-6, 42],
        [-6, 34],
        [-5, 22],
        [-8, 6],
      ],
      lower: [
        [-5, -4],
        [5, -4],
        [3, 6],
        [3, 18],
        [5, 23],
        [2, 28],
        [-5, 28],
        [-4, 22],
        [-4, 6],
      ],
      hoof: [
        [-5, 27],
        [3, 27],
        [4, 36],
        [-9, 36],
      ],
      facet: [
        [
          [1, 20],
          [7, 18],
          [5, 32],
          [6, 40],
          [2, 40],
        ],
        DARK,
        0.2,
      ],
    },
    B: {
      upper: [
        [-18, -10],
        [14, -12],
        [20, 4],
        [16, 16],
        [12, 28],
        [14, 40],
        [8, 46],
        [-1, 46],
        [-3, 34],
        [-6, 22],
        [-14, 10],
      ],
      lower: [
        [-6, -4],
        [6, -4],
        [5, 4],
        [3, 22],
        [4, 27],
        [1, 32],
        [-6, 32],
        [-5, 26],
        [-5, 6],
      ],
      hoof: [
        [-6, 30],
        [2, 30],
        [3, 38],
        [-10, 38],
      ],
      facet: [
        [
          [-14, 10],
          [2, 4],
          [-3, 34],
          [-6, 22],
        ],
        LIGHT,
        0.14,
      ],
    },
  };
  const HOOF_FILL = "#0A5FC8";
  const FAR_TINT = ["#0A6FE0", 0.45];

  const FX = 125;
  const sym = (half) => [
    ...half,
    ...half
      .slice(1, -1)
      .reverse()
      .map(([x, y]) => [2 * FX - x, y]),
  ];
  const mirror = (pts) => pts.map(([x, y]) => [2 * FX - x, y]);
  const frontLeg = (cx) => ({
    leg: [
      [-8, 0],
      [8, 0],
      [8, 18],
      [6, 42],
      [7, 50],
      [5, 56],
      [4.5, 76],
      [5.5, 84],
      [-5.5, 84],
      [-4.5, 76],
      [-5, 56],
      [-7, 50],
      [-6, 42],
      [-8, 18],
    ].map(([x, y]) => [cx + x * 1.15, 108 + y]),
    hoof: [
      [-5.5, 80],
      [5.5, 80],
      [7.5, 92],
      [-7.5, 92],
    ].map(([x, y]) => [cx + x * 1.15, 108 + y]),
    facet: [
      [
        [8, 10],
        [8, 18],
        [6, 42],
        [7, 50],
        [5, 56],
        [4.5, 76],
        [1, 76],
        [2, 30],
      ].map(([x, y]) => [cx + x * 1.15, 108 + y]),
      DARK,
      0.2,
    ],
    light: [
      [
        [-8, 10],
        [-8, 18],
        [-6, 42],
        [-7, 50],
        [-5, 56],
        [-4.5, 76],
        [-2, 76],
        [-3, 30],
      ].map(([x, y]) => [cx + x * 1.15, 108 + y]),
      LIGHT,
      0.14,
    ],
  });
  const LEG_L = frontLeg(FX - 13);
  const LEG_R = frontLeg(FX + 13);

  const FRONT = {
    body: sym([
      [125, 96],
      [112, 97],
      [101, 102],
      [93, 110],
      [90, 120],
      [92, 132],
      [98, 144],
      [108, 152],
      [125, 155],
    ]),
    maneL: [
      [113, 52],
      [107, 62],
      [102, 80],
      [105, 78],
      [101, 98],
      [110, 86],
      [112, 72],
    ],
    maneR: mirror([
      [113, 52],
      [107, 62],
      [102, 80],
      [105, 78],
      [101, 98],
      [110, 86],
      [112, 72],
    ]),
    chest: sym([
      [125, 56],
      [112, 60],
      [111, 72],
      [108, 88],
      [104, 100],
      [102, 112],
      [106, 122],
      [125, 128],
    ]),
    head: sym([
      [125, 22],
      [117, 23],
      [111, 28],
      [109.5, 37],
      [110.5, 47],
      [113.5, 57],
      [116, 66],
      [116.5, 76],
      [116, 83],
      [119, 87],
      [125, 88],
    ]),
    earL: [
      [111, 33],
      [105, 14],
      [118, 25],
    ],
    earR: mirror([
      [111, 33],
      [105, 14],
      [118, 25],
    ]),
    forelock: sym([
      [125, 20],
      [115, 25],
      [115.5, 33],
      [119, 40],
      [121.5, 52],
      [125, 45],
    ]),
    horn: [
      [125, 3],
      [129.5, 31],
      [120.5, 31],
    ],
    legL: LEG_L.leg,
    legR: LEG_R.leg,
    hoofL: LEG_L.hoof,
    hoofR: LEG_R.hoof,
  };
  const EYE = [
    [111.5, 37],
    [114, 35],
    [117, 36.5],
    [116.5, 40.5],
    [113, 41],
  ];
  const NOSTRIL = [
    [118, 79],
    [121, 78],
    [120.5, 83],
    [118, 82.5],
  ];
  const FRONT_EYES = [EYE, mirror(EYE)];
  const FRONT_NOSTRILS = [NOSTRIL, mirror(NOSTRIL)];
  const FRONT_FACETS = {
    body: [[FRONT.body, DARK, 0.26]],
    mane: [
      [FRONT.maneL, DARK, 0.2],
      [FRONT.maneR, DARK, 0.2],
    ],
    chest: [
      [FRONT.chest, DARK, 0.26],
      [
        [
          [109, 70],
          [141, 70],
          [136, 92],
          [125, 98],
          [114, 92],
        ],
        DARK,
        0.22,
      ],
      [
        [
          [111, 72],
          [125, 88],
          [125, 128],
          [106, 122],
          [102, 112],
          [104, 100],
          [108, 88],
        ],
        LIGHT,
        0.1,
      ],
      [
        [
          [139, 72],
          [125, 88],
          [125, 128],
          [144, 122],
          [148, 112],
          [146, 100],
          [142, 88],
        ],
        DARK,
        0.1,
      ],
    ],
    head: [
      [
        [
          [125, 22],
          [117, 23],
          [111, 28],
          [109.5, 37],
          [110.5, 47],
          [125, 54],
        ],
        LIGHT,
        0.16,
      ],
      [
        [
          [125, 22],
          [133, 23],
          [139, 28],
          [140.5, 37],
          [139.5, 47],
          [125, 54],
        ],
        DARK,
        0.1,
      ],
      [
        [
          [110.5, 47],
          [113.5, 57],
          [116, 66],
          [125, 72],
          [125, 54],
        ],
        LIGHT,
        0.08,
      ],
      [
        [
          [116, 66],
          [134, 66],
          [133.5, 76],
          [134, 83],
          [131, 87],
          [125, 88],
          [119, 87],
          [116, 83],
          [116.5, 76],
        ],
        LIGHT,
        0.14,
      ],
      [
        [
          [125, 72],
          [134, 66],
          [133.5, 76],
          [134, 83],
          [131, 87],
          [125, 88],
        ],
        DARK,
        0.12,
      ],
    ],
    ears: [
      [
        [
          [110, 30],
          [106, 18],
          [115, 25],
        ],
        DARK,
        0.3,
      ],
      [
        [
          [140, 30],
          [144, 18],
          [135, 25],
        ],
        DARK,
        0.3,
      ],
    ],
    forelock: [
      [
        [
          [125, 20],
          [115, 25],
          [115.5, 33],
          [119, 40],
          [121.5, 52],
          [125, 45],
        ],
        DARK,
        0.12,
      ],
      [
        [
          [125, 20],
          [135, 25],
          [134.5, 33],
          [131, 40],
          [128.5, 52],
          [125, 45],
        ],
        DARK,
        0.3,
      ],
    ],
    horn: [
      [
        [
          [125, 3],
          [129.5, 31],
          [125, 31],
        ],
        DARK,
        0.25,
      ],
      [
        [
          [123.6, 16],
          [126.8, 14],
          [127.7, 18],
          [123, 21],
        ],
        DARK,
        0.25,
      ],
      [
        [
          [122.4, 24],
          [128.2, 22],
          [129, 26],
          [121.8, 28],
        ],
        DARK,
        0.25,
      ],
    ],
    legs: [LEG_L.facet, LEG_L.light, LEG_R.facet, LEG_R.light],
  };

  const HAT_RED = "#E0343F";
  const HAT_DARK = "#7A0C1C";
  const HAT_WHITE = "#F6F8FC";
  const HAT_SHADE = "#B9C6DA";
  const HAT = [
    [
      [
        [60.5, 41.5],
        [62, 31],
        [65, 22],
        [70, 15.5],
        [77, 14.5],
        [83, 18],
        [80.5, 22.5],
        [76, 20.5],
        [76.5, 28],
        [77, 37.5],
      ],
      HAT_RED,
      1,
    ],
    [
      [
        [70, 15.5],
        [77, 14.5],
        [83, 18],
        [80.5, 22.5],
        [76, 20.5],
        [76.5, 28],
        [77, 37.5],
        [69, 39],
        [68, 24],
      ],
      HAT_DARK,
      0.3,
    ],
    [
      [
        [60, 44],
        [61.5, 37.5],
        [77.5, 33.5],
        [78.5, 39.5],
      ],
      HAT_WHITE,
      1,
    ],
    [
      [
        [61.5, 37.5],
        [77.5, 33.5],
        [78.5, 39.5],
        [68, 42],
      ],
      HAT_SHADE,
      0.35,
    ],
    [
      [
        [82.5, 18.5],
        [85.3, 19.7],
        [86.5, 22.5],
        [85.3, 25.3],
        [82.5, 26.5],
        [79.7, 25.3],
        [78.5, 22.5],
        [79.7, 19.7],
      ],
      HAT_WHITE,
      1,
    ],
    [
      [
        [85.3, 19.7],
        [86.5, 22.5],
        [85.3, 25.3],
        [82.5, 26.5],
        [82.5, 22.5],
      ],
      HAT_SHADE,
      0.35,
    ],
  ];
  const HAT_FRONT = [
    [
      [
        [127, 27.2],
        [127.3, 21],
        [129.3, 15.5],
        [132.4, 12.4],
        [136.7, 12.4],
        [139.4, 15.1],
        [137.9, 17.5],
        [135.1, 16.3],
        [135.1, 21.8],
        [136.3, 27.6],
      ],
      HAT_RED,
      1,
    ],
    [
      [
        [132.4, 12.4],
        [136.7, 12.4],
        [139.4, 15.1],
        [137.9, 17.5],
        [135.1, 16.3],
        [135.1, 21.8],
        [136.3, 27.6],
        [130.9, 28],
        [130.9, 18.6],
      ],
      HAT_DARK,
      0.3,
    ],
    [
      [
        [126.6, 27.6],
        [127.1, 22.9],
        [135.9, 25.7],
        [137.1, 29.9],
      ],
      HAT_WHITE,
      1,
    ],
    [
      [
        [127.1, 22.9],
        [135.9, 25.7],
        [137.1, 29.9],
        [130.9, 29.6],
      ],
      HAT_SHADE,
      0.35,
    ],
    [
      [
        [139, 14.7],
        [140.9, 15.5],
        [141.5, 17.3],
        [140.8, 19.1],
        [139, 19.8],
        [137.3, 19.1],
        [136.7, 17.3],
        [137.3, 15.5],
      ],
      HAT_WHITE,
      1,
    ],
    [
      [
        [140.9, 15.5],
        [141.5, 17.3],
        [140.8, 19.1],
        [139, 19.8],
        [139, 17.3],
      ],
      HAT_SHADE,
      0.35,
    ],
  ];

  let uid = 0;

  function el(tag, attrs = {}) {
    const node = document.createElementNS(NS, tag);
    for (const [k, v] of Object.entries(attrs)) node.setAttribute(k, String(v));
    return node;
  }

  function poly(points, [ox, oy] = [0, 0], attrs = {}) {
    return el("polygon", {
      points: points.map(([x, y]) => `${x + ox},${y + oy}`).join(" "),
      ...attrs,
    });
  }

  function part(name) {
    const g = el("g", { "data-part": name });
    const [x, y] = PIVOTS[name];
    g.style.transformBox = "view-box";
    g.style.transformOrigin = `${x}px ${y}px`;
    return g;
  }

  function addFacets(g, facets, offset = [0, 0]) {
    for (const [points, fill, opacity] of facets) g.append(poly(points, offset, { fill, opacity }));
  }

  function buildLeg(parts, side, fill, near) {
    const shape = LEGS[side[0]];
    const upper = part(`leg${side}1`);
    const lower = part(`leg${side}2`);
    const up = PIVOTS[`leg${side}1`];
    const low = PIVOTS[`leg${side}2`];
    const tint = (g, points, pivot) => {
      if (!near) g.append(poly(points, pivot, { fill: FAR_TINT[0], opacity: FAR_TINT[1] }));
    };
    upper.append(poly(shape.upper, up, { fill }));
    if (near) addFacets(upper, [shape.facet], up);
    tint(upper, shape.upper, up);
    lower.append(poly(shape.lower, low, { fill }));
    tint(lower, shape.lower, low);
    lower.append(poly(shape.hoof, low, { fill: HOOF_FILL }));
    upper.append(lower);
    parts[`leg${side}1`] = upper;
    parts[`leg${side}2`] = lower;
    return upper;
  }

  function buildPony(size = 80, { hat = false } = {}) {
    const id = `pony-grad-${++uid}`;
    const fill = `url(#${id})`;
    const svg = el("svg", {
      xmlns: NS,
      viewBox: `0 0 ${VB_W} ${VB_H}`,
      width: +((size * VB_W) / VB_H).toFixed(3),
      height: size,
      overflow: "visible",
    });

    const grad = el("linearGradient", {
      id,
      gradientUnits: "userSpaceOnUse",
      x1: 0,
      y1: 0,
      x2: VB_W,
      y2: VB_H,
    });
    grad.append(
      el("stop", { offset: 0, "stop-color": "#3DB0FF" }),
      el("stop", { offset: 1, "stop-color": "#0A84FF" }),
    );
    const defs = el("defs");
    defs.append(grad);
    svg.append(defs);

    const parts = {};
    for (const name of ["body", "neck", "head", "tail", "mane"]) parts[name] = part(name);

    parts.head.append(el("path", { d: HEAD_PATH, fill, "fill-rule": "evenodd" }));
    if (hat) addFacets(parts.head, HAT);
    parts.mane.append(poly(MANE, [0, 0], { fill }));
    addFacets(parts.mane, FACETS.mane);
    parts.neck.append(parts.mane, poly(NECK, [0, 0], { fill }));
    addFacets(parts.neck, FACETS.neck);
    parts.neck.append(parts.head);
    parts.tail.append(poly(TAIL, [0, 0], { fill }));
    addFacets(parts.tail, FACETS.tail);
    const torso = el("g");
    torso.append(poly(BODY, [0, 0], { fill }));
    addFacets(torso, FACETS.body);

    const body = parts.body;
    body.append(
      buildLeg(parts, "BR", fill, false),
      buildLeg(parts, "FR", fill, false),
      parts.tail,
      torso,
      parts.neck,
      buildLeg(parts, "BL", fill, true),
      buildLeg(parts, "FL", fill, true),
    );
    const front = buildFront(fill, hat);
    svg.append(body, front);
    return { el: svg, parts, front };
  }

  function buildFront(fill, hat) {
    const g = el("g", { "data-part": "front" });
    g.style.opacity = 0;
    g.style.transformBox = "view-box";
    g.style.transformOrigin = `${FX}px 100px`;
    const shape = (pts) => g.append(poly(pts, [0, 0], { fill }));
    shape(FRONT.body);
    addFacets(g, FRONT_FACETS.body);
    shape(FRONT.earL);
    shape(FRONT.earR);
    addFacets(g, FRONT_FACETS.ears);
    shape(FRONT.maneL);
    shape(FRONT.maneR);
    addFacets(g, FRONT_FACETS.mane);
    for (const [leg, hoof] of [
      ["legL", "hoofL"],
      ["legR", "hoofR"],
    ]) {
      shape(FRONT[leg]);
      g.append(poly(FRONT[hoof], [0, 0], { fill: HOOF_FILL }));
    }
    addFacets(g, FRONT_FACETS.legs);
    shape(FRONT.chest);
    addFacets(g, FRONT_FACETS.chest);
    const headPath = (pts) => `M${pts.map(([x, y]) => `${x} ${y}`).join(" L")}Z`;
    g.append(
      el("path", {
        d: [FRONT.head, ...FRONT_NOSTRILS].map(headPath).join(""),
        fill,
        "fill-rule": "evenodd",
      }),
    );
    addFacets(g, FRONT_FACETS.head);
    for (const eye of FRONT_EYES) g.append(poly(eye, [0, 0], { fill: "#072B66" }));
    shape(FRONT.forelock);
    addFacets(g, FRONT_FACETS.forelock);
    shape(FRONT.horn);
    addFacets(g, FRONT_FACETS.horn);
    if (hat) addFacets(g, HAT_FRONT);
    return g;
  }
  const STAND = Object.fromEntries(PART_NAMES.map((n) => [n, 0]));
  const clamp01 = (t) => Math.min(1, Math.max(0, t));
  function easeInOut(t) {
    const x = clamp01(t);
    return x * x * (3 - 2 * x);
  }
  function lerpPose(a, b, t) {
    const k = clamp01(t);
    const out = {};
    for (const name of new Set([...Object.keys(a), ...Object.keys(b)])) {
      const from = name in a ? a[name] : (STAND[name] ?? 0);
      const to = name in b ? b[name] : (STAND[name] ?? 0);
      out[name] = from + (to - from) * k;
    }
    return out;
  }
  function applyPose(parts, pose) {
    for (const [name, deg] of Object.entries(pose)) {
      if (parts[name]) parts[name].style.transform = "rotate(" + deg + "deg)";
    }
  }
  const pose = (p) => ({ ...STAND, ...p });
  function legAt(p, { A, flex, duty }) {
    if (p < duty) return [A * (1 - (2 * p) / duty), 0];
    const s = (p - duty) / (1 - duty);
    return [-A + 2 * A * s, -flex * Math.sin(Math.PI * s)];
  }
  const frac = (x) => x - Math.floor(x);
  function gait({ duration, speed, n, phase, front, hind, extra }) {
    const keys = [];
    for (let i = 0; i <= n; i++) {
      const p = (i % n) / n;
      const parts = {};
      for (const leg of ["FL", "FR", "BL", "BR"]) {
        const [upper, lower] = legAt(frac(p + phase[leg]), leg[0] === "F" ? front : hind);
        parts[`leg${leg}1`] = upper;
        parts[`leg${leg}2`] = lower;
      }
      const w = 2 * Math.PI * p;
      keys.push({ t: (i / n) * duration, pose: pose({ ...parts, ...extra(w) }) });
    }
    return { keys, duration, speed, loop: true };
  }
  const at = (duration, list) => list.map(([f, p]) => ({ t: f * duration, pose: pose(p) }));
  const LIE = {
    neck: -45,
    head: 12,
    legFL1: 70,
    legFL2: -150,
    legFR1: 62,
    legFR2: -145,
    legBL1: 70,
    legBL2: -155,
    legBR1: 64,
    legBR2: -150,
    tail: -40,
    mane: -3,
  };
  const GRAZE = {
    body: -8,
    neck: -76,
    head: -8,
    legFL1: 20,
    legFL2: -14,
    legFR1: 0,
    legFR2: -4,
    legBL1: 8,
    legBR1: 8,
    tail: 2,
  };
  const SNIFF = { body: -4, neck: -36, head: -2 };
  const JUMP_AIR = [0.3, 0.8];
  const ACTIONS = {
    walk: gait({
      duration: 1.0,
      speed: 40,
      n: 12,
      phase: { BL: 0, FL: 0.75, BR: 0.5, FR: 0.25 },
      front: { A: 16, flex: 45, duty: 0.65 },
      hind: { A: 15, flex: 35, duty: 0.65 },
      extra: (w) => ({
        neck: -2 + 2 * Math.sin(2 * w),
        head: Math.sin(2 * w),
        tail: 3 * Math.sin(w),
        mane: Math.sin(2 * w),
      }),
    }),
    trot: gait({
      duration: 0.6,
      speed: 75,
      n: 8,
      phase: { FL: 0, BR: 0, FR: 0.5, BL: 0.5 },
      front: { A: 22, flex: 70, duty: 0.5 },
      hind: { A: 20, flex: 50, duty: 0.5 },
      extra: (w) => ({
        body: 1.5 * Math.sin(2 * w),
        neck: -3 + 2 * Math.sin(2 * w),
        tail: -8 + 4 * Math.sin(2 * w),
        mane: 3 * Math.sin(2 * w),
      }),
    }),
    run: gait({
      duration: 0.5,
      speed: 120,
      n: 8,
      phase: { BR: 0, BL: 0.7, FR: 0.7, FL: 0.45 },
      front: { A: 30, flex: 85, duty: 0.45 },
      hind: { A: 28, flex: 60, duty: 0.45 },
      extra: (w) => ({
        body: 4 * Math.sin(w),
        neck: -1 - 3 * Math.sin(w),
        head: 2 * Math.sin(w),
        tail: -18 + 6 * Math.sin(w),
        mane: 5 * Math.sin(w),
      }),
    }),
    gallop: gait({
      duration: 0.42,
      speed: 170,
      n: 8,
      phase: { BR: 0, BL: 0.9, FR: 0.55, FL: 0.45 },
      front: { A: 42, flex: 105, duty: 0.35 },
      hind: { A: 40, flex: 80, duty: 0.35 },
      extra: (w) => ({
        body: 7 * Math.sin(w),
        neck: -14 - 5 * Math.sin(w),
        head: 4 + 3 * Math.sin(w),
        tail: -34 + 8 * Math.sin(w),
        mane: 10 * Math.sin(w),
      }),
    }),
    jump: {
      duration: 1.0,
      speed: 200,
      lift: 0.45,
      loop: false,
      keys: at(1.0, [
        [0, {}],
        [
          0.22,
          {
            body: -4,
            neck: -10,
            legFL1: 12,
            legFL2: -20,
            legFR1: 10,
            legFR2: -18,
            legBL1: 22,
            legBL2: -40,
            legBR1: 20,
            legBR2: -38,
            tail: 5,
          },
        ],
        [
          JUMP_AIR[0],
          {
            body: 10,
            neck: 4,
            legFL1: 55,
            legFL2: -100,
            legFR1: 48,
            legFR2: -95,
            legBL1: -38,
            legBL2: 4,
            legBR1: -34,
            legBR2: 2,
            tail: -15,
          },
        ],
        [
          0.55,
          {
            body: 0,
            neck: -4,
            legFL1: 62,
            legFL2: -115,
            legFR1: 56,
            legFR2: -110,
            legBL1: 40,
            legBL2: -75,
            legBR1: 36,
            legBR2: -70,
            tail: -25,
            mane: 6,
          },
        ],
        [
          JUMP_AIR[1],
          {
            body: -9,
            neck: 6,
            legFL1: 10,
            legFL2: -2,
            legFR1: 14,
            legFR2: -4,
            legBL1: -6,
            legBL2: -30,
            legBR1: -4,
            legBR2: -30,
            tail: -30,
            mane: -4,
          },
        ],
        [
          0.9,
          {
            body: -2,
            neck: -4,
            legFL1: 4,
            legFL2: -10,
            legFR1: 6,
            legFR2: -12,
            legBL1: 12,
            legBL2: -24,
            legBR1: 10,
            legBR2: -22,
            tail: -10,
          },
        ],
        [1, {}],
      ]),
    },
    buck: {
      duration: 1.1,
      speed: 0,
      loop: false,
      keys: at(1.1, [
        [0, {}],
        [
          0.25,
          {
            body: -3,
            neck: -8,
            legBL1: 16,
            legBL2: -28,
            legBR1: 14,
            legBR2: -26,
            legFL1: 3,
            legFR1: 3,
          },
        ],
        [
          0.5,
          {
            body: -16,
            neck: -20,
            head: -6,
            legFL1: 46,
            legFL2: -48,
            legFR1: 42,
            legFR2: -44,
            legBL1: -70,
            legBL2: 12,
            legBR1: -60,
            legBR2: 6,
            tail: -45,
            mane: 6,
          },
        ],
        [
          0.72,
          {
            body: -10,
            neck: -14,
            legFL1: 30,
            legFL2: -32,
            legFR1: 28,
            legFR2: -30,
            legBL1: -40,
            legBL2: -10,
            legBR1: -34,
            legBR2: -12,
            tail: -30,
          },
        ],
        [1, {}],
      ]),
    },
    rear: {
      duration: 1.8,
      speed: 0,
      loop: false,
      keys: at(1.8, [
        [0, {}],
        [0.2, { body: -3, neck: -8, legBL1: 10, legBL2: -16, legBR1: 9, legBR2: -15, tail: 4 }],
        [
          0.45,
          {
            body: 38,
            neck: -12,
            head: 4,
            legFL1: 40,
            legFL2: -95,
            legFR1: 55,
            legFR2: -100,
            legBL1: -18,
            legBL2: -30,
            legBR1: -21,
            legBR2: -26,
            tail: 8,
            mane: -4,
          },
        ],
        [
          0.62,
          {
            body: 40,
            neck: -8,
            head: 6,
            legFL1: 58,
            legFL2: -105,
            legFR1: 38,
            legFR2: -90,
            legBL1: -19,
            legBL2: -30,
            legBR1: -22,
            legBR2: -26,
            tail: 10,
            mane: 4,
          },
        ],
        [
          0.78,
          {
            body: 37,
            neck: -12,
            head: 2,
            legFL1: 42,
            legFL2: -95,
            legFR1: 56,
            legFR2: -102,
            legBL1: -17,
            legBL2: -30,
            legBR1: -20,
            legBR2: -26,
            tail: 8,
            mane: -3,
          },
        ],
        [1, {}],
      ]),
    },
    tailswish: {
      duration: 1.4,
      speed: 0,
      loop: true,
      keys: at(1.4, [
        [0, { neck: -3 }],
        [0.25, { tail: -28, neck: -3 }],
        [0.55, { tail: 14, neck: -5, head: 2 }],
        [0.8, { tail: -16, neck: -4 }],
        [1, { neck: -3 }],
      ]),
    },
    rest: {
      duration: 2.6,
      speed: 0,
      loop: true,
      keys: at(2.6, [
        [0, { neck: -10, legBR1: 6, legBR2: -14, tail: 4 }],
        [0.5, { body: -0.8, neck: -15, head: 4, legBR1: 6, legBR2: -14, tail: 6 }],
        [1, { neck: -10, legBR1: 6, legBR2: -14, tail: 4 }],
      ]),
    },
    lie: {
      duration: 3.0,
      speed: 0,
      loop: true,
      sink: 0.24,
      keys: at(3.0, [
        [0, LIE],
        [
          0.5,
          { ...LIE, body: 0.8, neck: LIE.neck + 1.5, head: LIE.head + 0.8, mane: LIE.mane + 1 },
        ],
        [1, LIE],
      ]),
    },
    graze: {
      duration: 3.5,
      speed: 0,
      loop: false,
      keys: at(3.5, [
        [0, {}],
        [0.2, GRAZE],
        ...[0.3, 0.4, 0.5, 0.6, 0.7].map((f, i) => [
          f,
          { ...GRAZE, neck: GRAZE.neck + (i % 2 ? 0 : 3), head: GRAZE.head + (i % 2 ? 0 : -5) },
        ]),
        [0.78, { ...GRAZE, tail: -30 }],
        [0.86, { ...GRAZE, tail: 8 }],
        [0.92, { ...GRAZE, tail: -12 }],
        [1, {}],
      ]),
    },
    snort: {
      duration: 1.0,
      speed: 0,
      loop: false,
      keys: at(1.0, [
        [0, {}],
        [0.15, { neck: -5, head: -3, legFL1: 32, legFL2: -55, tail: -10 }],
        [0.32, { neck: 16, head: 10, body: 2, legFL1: 38, legFL2: -40, tail: -35 }],
        [0.45, { neck: 12, head: 6, legFL1: 0, legFL2: 0, tail: -40 }],
        [0.6, { neck: 14, head: 8, tail: -38 }],
        [0.8, { neck: 3, head: 1, tail: -20 }],
        [1, {}],
      ]),
    },
    sniff: {
      duration: 2.0,
      speed: 0,
      loop: false,
      keys: at(2.0, [
        [0, {}],
        [0.2, SNIFF],
        ...[0.3, 0.4, 0.5, 0.6, 0.7, 0.8].map((f, i) => [
          f,
          { ...SNIFF, head: SNIFF.head + (i % 2 ? 0 : 4), neck: SNIFF.neck + (i % 2 ? 0 : 1.5) },
        ]),
        [1, {}],
      ]),
    },
  };
  const ACTION_NAMES = Object.keys(ACTIONS);
  function localTime(a, time) {
    const t = Number.isFinite(time) ? time : 0;
    if (a.loop) return frac(t / a.duration) * a.duration;
    return Math.min(a.duration, Math.max(0, t));
  }
  function poseAt(name, time) {
    const a = ACTIONS[name];
    const t = localTime(a, time);
    const { keys } = a;
    let i = 1;
    while (i < keys.length - 1 && keys[i].t < t) i++;
    const k0 = keys[i - 1];
    const k1 = keys[i];
    return lerpPose(k0.pose, k1.pose, easeInOut((t - k0.t) / (k1.t - k0.t)));
  }
  function heightAt(name, time) {
    const a = ACTIONS[name];
    if (!a.lift) return 0;
    const u = (localTime(a, time) / a.duration - JUMP_AIR[0]) / (JUMP_AIR[1] - JUMP_AIR[0]);
    return u > 0 && u < 1 ? a.lift * Math.sin(Math.PI * u) : 0;
  }
  function travelOf(name) {
    const a = ACTIONS[name];
    return a.speed * a.duration * (a.lift ? JUMP_AIR[1] - JUMP_AIR[0] : 1);
  }
  function speedAt(name, time) {
    const a = ACTIONS[name];
    if (!a.lift) return a.speed;
    return heightAt(name, time) > 0 ? a.speed : 0;
  }
  const shift =
    ([ox, oy]) =>
    ([x, y]) => [x + ox, y + oy];
  const SOLE = VB_H;
  const pairs = (path) => {
    const n = path.match(/-?\d+(?:\.\d+)?/g).map(Number);
    return Array.from({ length: n.length / 2 }, (_, i) => [n[2 * i], n[2 * i + 1]]);
  };
  const LEG_CHAINS = ["FL", "FR", "BL", "BR"].flatMap((s) => {
    const g = LEGS[s[0]];
    const up = PIVOTS[`leg${s}1`];
    const low = PIVOTS[`leg${s}2`];
    return [
      [g.upper.map(shift(up)), [`leg${s}1`, "body"]],
      [[...g.lower, ...g.hoof].map(shift(low)), [`leg${s}2`, `leg${s}1`, "body"]],
    ];
  });
  const TOP_CHAINS = [
    [pairs(HEAD_PATH), ["head", "neck", "body"]],
    [MANE, ["mane", "neck", "body"]],
    [NECK, ["neck", "body"]],
  ];
  const TAIL_CHAINS = [[TAIL, ["tail", "body"]]];
  function place(pose, chain, [x, y]) {
    for (const name of chain) {
      const r = ((pose[name] ?? 0) * Math.PI) / 180;
      const [cx, cy] = PIVOTS[name];
      const dx = x - cx;
      const dy = y - cy;
      x = cx + dx * Math.cos(r) - dy * Math.sin(r);
      y = cy + dx * Math.sin(r) + dy * Math.cos(r);
    }
    return [x, y];
  }
  function extreme(pose, chains, pick, start) {
    let v = start;
    for (const [points, chain] of chains)
      for (const p of points) v = pick(v, place(pose, chain, p)[1]);
    return v;
  }
  function bounds(pose) {
    return {
      legs: extreme(pose, LEG_CHAINS, Math.max, -Infinity),
      tail: extreme(pose, TAIL_CHAINS, Math.max, -Infinity),
      top: extreme(pose, TOP_CHAINS, Math.min, Infinity),
    };
  }
  function groundLift(pose) {
    return Math.max(0, extreme(pose, LEG_CHAINS, Math.max, -Infinity) - SOLE) / VB_H;
  }
  function topOverflow(pose) {
    return Math.max(0, -extreme(pose, TOP_CHAINS, Math.min, Infinity)) / VB_H;
  }
  const WEIGHTS = {
    walk: 2.5,
    trot: 4,
    run: 5,
    gallop: 4,
    rest: 1.5,
    tailswish: 1.5,
    jump: 1,
    buck: 1,
    rear: 1,
    graze: 0.8,
    snort: 0.6,
  };
  const IN_PLACE = new Set(["rest", "tailswish", "buck", "rear", "graze", "snort", "lie", "sniff"]);
  const SINK_TIME = 0.3;
  const MAX_DT = 0.1;
  const BLEND = 0.2;
  const FLEE_ROOM = 0.8;
  const FLEE_HOLD = 0.5;
  const BUSY = new Set(["jump", "rear", "buck", "snort", "sniff"]);
  const SNIFF_EVERY = 6;
  const WIDTH_PER_SIZE = 1.25;
  const unit = (r) => (Number.isFinite(r) ? Math.min(Math.max(r, 0), 1 - 1e-12) : 0);
  function pickAction(rand, prev) {
    const names = Object.keys(WEIGHTS).filter((n) => n !== prev);
    const total = names.reduce((s, n) => s + WEIGHTS[n], 0);
    let r = unit(rand()) * total;
    for (const n of names) {
      r -= WEIGHTS[n];
      if (r < 0) return n;
    }
    return names.at(-1);
  }
  function fitY(y, top, size, viewH) {
    const room = Number.isFinite(viewH) && viewH > 0 ? viewH - size - top : Infinity;
    return Math.min(Math.max(y, 0), Math.max(0, room));
  }
  function createDirector({ width, size, rand = Math.random }) {
    const sz = Number.isFinite(size) && size > 0 ? size : 80;
    const scale = sz / 80;
    const range = (w) => (Number.isFinite(w) ? Math.max(0, w - WIDTH_PER_SIZE * sz) : 0);
    let maxX = range(width);
    let x = maxX / 2;
    let dir = unit(rand()) < 0.5 ? -1 : 1;
    let action = null;
    let time = 0;
    let runLength = 0;
    let lastPose = null;
    let fromPose = null;
    let clock = 0;
    let sniffedAt = -Infinity;
    let sinkK = 0;
    let sinkMax = 0;
    function begin(prev) {
      action = pickAction(rand, prev);
      const a = ACTIONS[action];
      runLength = a.loop ? a.duration * (2 + Math.floor(unit(rand()) * 4)) : a.duration;
      if (IN_PLACE.has(prev) && unit(rand()) < 0.5) dir = -dir;
      fromPose = lastPose;
      faceInward();
    }
    function faceInward() {
      const a = ACTIONS[action];
      if (a.speed <= 0 || maxX <= 0) return;
      if (a.loop) {
        if (x >= maxX) dir = -1;
        else if (x <= 0) dir = 1;
        return;
      }
      const ahead = dir === 1 ? maxX - x : x;
      if (ahead < travelOf(action) * scale) dir = maxX - x >= x ? 1 : -1;
    }
    begin(null);
    function step(dt) {
      const d = Number.isFinite(dt) ? Math.min(MAX_DT, Math.max(0, dt)) : 0;
      time += d;
      clock += d;
      while (time >= runLength) {
        time -= runLength;
        begin(action);
      }
      if (maxX <= 0) {
        x = 0;
      } else {
        const speed = speedAt(action, time);
        const turn = speed > 0 && ACTIONS[action].loop;
        x += dir * speed * scale * d;
        if (x >= maxX) {
          x = maxX;
          if (turn) dir = -1;
        } else if (x <= 0) {
          x = 0;
          if (turn) dir = 1;
        }
      }
      let pose = poseAt(action, time);
      if (fromPose && time < BLEND) pose = lerpPose(fromPose, pose, easeInOut(time / BLEND));
      lastPose = pose;
      const y = Math.max(heightAt(action, time), groundLift(pose)) * sz;
      const want = ACTIONS[action].sink;
      if (want) sinkMax = want * sz;
      const goal = want && runLength - time > SINK_TIME ? 1 : 0;
      const stride = d / SINK_TIME;
      sinkK += Math.min(stride, Math.max(-stride, goal - sinkK));
      return {
        x,
        y,
        dir,
        pose,
        action,
        time,
        top: topOverflow(pose) * sz,
        sink: sinkMax * easeInOut(sinkK),
      };
    }
    function setWidth(w, nx) {
      maxX = range(w);
      x = Math.min(Math.max(Number.isFinite(nx) ? nx : x, 0), maxX);
    }
    function play(name) {
      if (!Object.hasOwn(ACTIONS, name)) return;
      action = name;
      time = 0;
      const a = ACTIONS[name];
      runLength = a.loop ? a.duration * (2 + Math.floor(unit(rand()) * 4)) : a.duration;
      fromPose = lastPose;
      faceInward();
    }
    function flee(away) {
      if (action === "jump") return;
      const room = away === 1 ? maxX - x : x;
      if (room < FLEE_ROOM * sz) {
        play("jump");
        return;
      }
      if (action === "gallop" && dir === away) {
        runLength = Math.max(runLength, time + FLEE_HOLD);
        return;
      }
      play("gallop");
      dir = away;
      runLength = time + FLEE_HOLD;
    }
    function hold(name) {
      if (action !== name) play(name);
      else runLength = Math.max(runLength, time + FLEE_HOLD);
    }
    function follow(cx) {
      if (BUSY.has(action) || maxX <= 0) return;
      const w = WIDTH_PER_SIZE * sz;
      const want = cx > x + 0.5 * w ? 1 : -1;
      const d = cx - (x + (want === 1 ? 0.9 : 0.1) * w);
      if (Math.abs(d) < 0.3 * sz || (want === 1 ? d < 0 : d > 0)) {
        dir = want;
        if (clock - sniffedAt > SNIFF_EVERY) {
          sniffedAt = clock;
          play("sniff");
        } else {
          hold("rest");
        }
        return;
      }
      const gait = Math.abs(d) > 3 * sz ? "trot" : "walk";
      if (action !== gait || dir !== want) {
        play(gait);
        dir = want;
      }
      runLength = Math.max(runLength, time + FLEE_HOLD);
    }
    function face(way) {
      if (way === 1 || way === -1) dir = way;
    }
    return { step, setWidth, play, flee, hold, follow, face };
  }
  const HOP_TIME = 0.55;
  function pickPlatform(rects, viewH, minTop, slack = 24) {
    let best = null;
    for (const r of rects) {
      if (!(r.right > r.left) || r.top < minTop || r.top >= viewH || r.bottom < viewH - slack)
        continue;
      if (!best || r.top > best.top) best = r;
    }
    return best;
  }
  function hopHeight(from, to, size) {
    return Math.max(0.5 * size, 0.3 * Math.abs(to - from));
  }
  function hopY(u, from, to, height) {
    const k = Math.min(1, Math.max(0, u));
    return from + (to - from) * easeInOut(k) + 4 * height * k * (1 - k);
  }
  const SLOW = 250;
  const FAST = 1400;
  const SCARE_DIST = 0.5;
  const NEAR = 1.2;
  const CURIOUS_AFTER = 2;
  const CURIOUS_RANGE = 3.5;
  const KEEP_RANGE = 6;
  const GAZE_RANGE = 8;
  const GAZE_MAX = 14;
  const REAR_EVERY = 5;
  const TOAST_EVERY = 1.5;
  const IDLE_SLEEP = 90;
  const AWAY_JOY = 20;
  const JOY_RUN_AT = 0.9;
  const JOY_RUN_FOR = 1.3;
  const GAZE_ACTIONS = new Set(["rest", "tailswish", "walk"]);
  const TOAST_ACTION = { success: "jump", error: "snort", warning: "sniff" };
  const PAGE_EVERY = 1;
  const clamp = (v, lo, hi) => Math.min(hi, Math.max(lo, v));
  function createMood() {
    let prev = null;
    let speed = 0;
    let still = 0;
    let following = false;
    let sleeping = false;
    let gaze = 0;
    let rearIn = 0;
    let toastIn = 0;
    let pageIn = 0;
    let joy = null;
    return function update(input) {
      const { size, cursor, box, dir, action, idle, pressed, returned, toast } = input;
      const page = input.page || {
        events: [],
        dialog: false,
        reading: false,
        typing: false,
        searchX: 0,
      };
      const dt = Number.isFinite(input.dt) ? Math.max(0, input.dt) : 0;
      const out = { flee: 0, follow: null, hold: null, play: null, face: 0, gaze: 0 };
      rearIn = Math.max(0, rearIn - dt);
      pageIn = Math.max(0, pageIn - dt);
      toastIn = Math.max(0, toastIn - dt);
      if (cursor && prev && dt > 0) {
        const v = Math.hypot(cursor.x - prev.x, cursor.y - prev.y) / dt;
        speed += (v - speed) * Math.min(1, dt * 8);
      } else if (!cursor) {
        speed = 0;
      }
      prev = cursor ? { x: cursor.x, y: cursor.y } : null;
      still = cursor && speed < SLOW ? still + dt : 0;
      const awake = sleeping && idle < 1;
      if (awake) sleeping = false;
      if (!sleeping && idle >= IDLE_SLEEP) sleeping = true;
      if (returned >= AWAY_JOY) {
        sleeping = false;
        joy = { t: 0, to: cursor ? cursor.x : (box.left + box.right) / 2 };
        out.play = "jump";
      } else if (toast && toastIn === 0 && Object.hasOwn(TOAST_ACTION, toast)) {
        sleeping = false;
        toastIn = TOAST_EVERY;
        out.play = TOAST_ACTION[toast];
      }
      const mid = (box.left + box.right) / 2;
      const toward = (x) => (x > mid ? 1 : -1);
      if (!out.play && pageIn === 0) {
        for (const ev of page.events) {
          if (ev.type === "tab") out.play = "snort";
          else if (ev.type === "nomatch") out.play = "snort";
          else if (ev.type === "switch") {
            out.play = ev.on ? "tailswish" : "sniff";
            out.face = toward(ev.x);
          }
          if (out.play) {
            sleeping = false;
            pageIn = PAGE_EVERY;
            break;
          }
        }
      }
      const pageHold = page.reading ? "lie" : page.dialog || page.typing ? "rest" : null;
      if (page.typing && !out.face) out.face = toward(page.searchX);
      if (joy) {
        joy.t += dt;
        if (joy.t >= JOY_RUN_AT && joy.t < JOY_RUN_AT + JOY_RUN_FOR)
          out.flee = joy.to > (box.left + box.right) / 2 ? 1 : -1;
        if (joy.t >= JOY_RUN_AT + JOY_RUN_FOR) joy = null;
        return out;
      }
      if (out.play) return out;
      if (sleeping) {
        out.hold = "lie";
        return out;
      }
      if (!cursor) {
        following = false;
        if (awake) out.play = "snort";
        else out.hold = pageHold;
        return out;
      }
      const dx = Math.max(box.left - cursor.x, 0, cursor.x - box.right);
      const dy = Math.max(box.top - cursor.y, 0, cursor.y - box.bottom);
      const dist = Math.hypot(dx, dy);
      const side = cursor.x < (box.left + box.right) / 2 ? 1 : -1;
      if (speed >= FAST && dist < NEAR * size && rearIn === 0) {
        rearIn = REAR_EVERY;
        following = false;
        out.play = "rear";
        return out;
      }
      if (speed >= SLOW && dist < SCARE_DIST * size) {
        following = false;
        out.flee = side;
        return out;
      }
      if (pressed) {
        following = true;
      } else if (following) {
        following = dist < KEEP_RANGE * size && speed < 3 * SLOW;
      } else {
        following = still >= CURIOUS_AFTER && dist < CURIOUS_RANGE * size;
      }
      if (following) out.follow = cursor.x;
      else if (!out.hold) out.hold = pageHold;
      if (awake && !following) out.play = "snort";
      if (dist < GAZE_RANGE * size && GAZE_ACTIONS.has(action) && !following) {
        const nose = dir === 1 ? box.right : box.left;
        const inFront = (cursor.x - (box.left + box.right) / 2) * dir >= 0;
        const headY = box.top + 0.35 * size;
        const deg =
          (Math.atan2(headY - cursor.y, Math.max(Math.abs(cursor.x - nose), 0.5 * size)) * 180) /
          Math.PI;
        gaze +=
          ((inFront ? clamp(deg * 0.7, -GAZE_MAX, GAZE_MAX) : 0) - gaze) * Math.min(1, dt * 6);
      } else {
        gaze += (0 - gaze) * Math.min(1, dt * 6);
      }
      out.gaze = gaze;
      return out;
    };
  }
  const DUST_CAP = 40;
  const DUST_LIFE = 0.5;
  const DUST_GAP = 0.07;
  const DUST_COLOR = "#bfe3ff";
  const DUST_ALPHA = 0.55;
  function createDust(size, rand = Math.random) {
    const particles = [];
    let wait = 0;
    function spawn(x, y, dir, strength = 1) {
      if (particles.length >= DUST_CAP) return false;
      const k = 0.5 + 0.5 * Math.min(1, Math.max(0, strength));
      particles.push({
        x,
        y,
        age: 0,
        r: 0.04 * size,
        o: DUST_ALPHA,
        vx: -dir * (0.25 + 0.2 * rand()) * size * k + (rand() - 0.5) * 0.1 * size,
        vy: (0.12 + 0.12 * rand()) * size * k,
      });
      return true;
    }
    function trail(x, y, dir, strength) {
      if (wait > 0) return false;
      wait = DUST_GAP;
      return spawn(x, y, dir, strength);
    }
    function burst(x, y, count = 6) {
      for (let i = 0; i < count; i++) spawn(x, y, i % 2 ? 1 : -1, 1);
    }
    function update(dt) {
      if (!(dt > 0)) return;
      wait -= dt;
      for (let i = particles.length - 1; i >= 0; i--) {
        const p = particles[i];
        p.age += dt;
        if (p.age >= DUST_LIFE) {
          particles.splice(i, 1);
          continue;
        }
        const u = p.age / DUST_LIFE;
        p.x += p.vx * dt;
        p.y += p.vy * dt;
        p.r = size * (0.04 + 0.06 * u);
        p.o = DUST_ALPHA * (1 - u);
      }
    }
    function clear() {
      particles.length = 0;
      wait = 0;
    }
    return { spawn, trail, burst, update, clear, particles };
  }
  const SVG_NS = "http://www.w3.org/2000/svg";
  const BLADES = 11;
  const SPROUT = [0.13, 0.22];
  const NIBBLE = [0.3, 0.7];
  const LEFT = 0.55;
  const LINGER = 2.5;
  const ramp = (v, [a, b]) => Math.min(1, Math.max(0, (v - a) / (b - a)));
  function grassPresence(t, duration) {
    if (!(duration > 0) || !Number.isFinite(t) || t < 0) return 0;
    const f = t / duration;
    return ramp(f, SPROUT) * (1 - (1 - LEFT) * ramp(f, NIBBLE));
  }
  function createGrass(size) {
    const u = size / 80;
    const el = document.createElementNS(SVG_NS, "svg");
    el.setAttribute("aria-hidden", "true");
    el.style.cssText =
      "position:absolute;left:0;bottom:0;width:1px;height:1px;overflow:visible;pointer-events:none";
    const g = document.createElementNS(SVG_NS, "g");
    g.style.display = "none";
    el.append(g);
    const colors = ["#3fa75a", "#5cc16f", "#2f8f4e"];
    for (let i = 0; i < BLADES; i++) {
      const f = i / (BLADES - 1) - 0.5;
      const h = (9 + ((i * 7) % 5) * 2.5) * u;
      const lean = (f * 9 + ((i * 3) % 4) - 1.5) * u;
      const w = 1.6 * u;
      const p = document.createElementNS(SVG_NS, "polygon");
      p.setAttribute(
        "points",
        `${f * 34 * u - w},0 ${f * 34 * u + lean},${-h} ${f * 34 * u + w},0`,
      );
      p.setAttribute("fill", colors[i % colors.length]);
      g.append(p);
    }
    let k = 0;
    let cx = 0;
    let cy = 0;
    let held = 0;
    let after = 0;
    return {
      el,
      update(dt, graze, x, base) {
        let goal;
        if (graze) {
          goal = grassPresence(graze.time, graze.duration);
          if (k === 0) {
            cx = x;
            cy = base;
          }
          held = goal;
          after = 0;
        } else {
          after += Math.max(0, dt);
          goal = Math.abs(x - cx) < 0.5 * size && after < LINGER ? held : 0;
        }
        k += (goal - k) * Math.min(1, Math.max(0, dt) * 12);
        if (k < 0.01) k = 0;
        g.style.display = k ? "" : "none";
        if (k)
          g.setAttribute(
            "transform",
            `translate(${cx.toFixed(1)} ${(-cy).toFixed(1)}) scale(1 ${k.toFixed(2)})`,
          );
      },
    };
  }
  const TURN_TIME = 0.45;
  const MIN_WIDTH = 0.5;
  const YAW = 24;
  function turnAt(u, from, to) {
    const k = Math.min(1, Math.max(0, Number.isFinite(u) ? u : 0));
    const e = easeInOut(k);
    const raw = from + (to - from) * e;
    const sx = Math.abs(raw) < MIN_WIDTH ? (e < 0.5 ? from : to) * MIN_WIDTH : raw;
    const rise = Math.sin(Math.PI * k);
    const f = Math.min(1, Math.max(0, (rise - 0.55) / 0.35));
    return { sx, rise, yaw: YAW * rise * to, front: f * f * (3 - 2 * f) };
  }
  const STORAGE_KEY = "unicorn-pony";
  const ZONE = 64;
  const HIDE_DELAY = 500;
  const TAP_REVEAL = 3000;
  const STYLE = `
.upt-zone{position:fixed;left:0;bottom:0;width:${ZONE}px;height:${ZONE}px;z-index:2147483001;pointer-events:none}
.upt-zone[data-off]{pointer-events:auto}
.upt{position:absolute;left:max(12px,env(safe-area-inset-left));bottom:max(12px,env(safe-area-inset-bottom));box-sizing:border-box;width:40px;height:40px;display:inline-flex;align-items:center;justify-content:center;padding:0;border-radius:.5rem;border:1px solid var(--bg-light-extra,#282a39);background:var(--bg-light,#20202c);color:var(--text-2,#aaa);cursor:pointer;pointer-events:auto;transition:background-color .1s ease-in-out,color .1s ease-in-out,opacity .2s ease,transform .2s ease}
.upt:hover{background:var(--bg-light-extra,#282a39);color:var(--text,#fff)}
.upt[aria-pressed=true]{color:var(--accent,#42bdf9)}
.upt[data-hidden]{opacity:0;pointer-events:none;transform:translateY(6px)}
.upt:focus-visible{outline:2px solid var(--accent,#42bdf9);outline-offset:2px}
@media (pointer:coarse){.upt{width:46px;height:46px;border-color:color-mix(in oklab,var(--accent,#42bdf9) 50%,var(--bg-light-extra,#282a39));box-shadow:0 2px 12px rgba(0,0,0,.55)}}
`;
  const PAW =
    '<svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">' +
    '<circle cx="11" cy="4" r="2"/><circle cx="18" cy="8" r="2"/><circle cx="20" cy="16" r="2"/>' +
    '<path d="M9 10a5 5 0 0 1 5 5v3.5a3.5 3.5 0 0 1-6.84 1.045Q6.52 17.48 4.46 16.84A3.5 3.5 0 0 1 5.5 10Z"/></svg>';
  function parseChoice(search) {
    const v = new URLSearchParams(search || "").get("pony");
    if (v === "off" || v === "0") return false;
    if (v === "on" || v === "1") return true;
    return null;
  }
  function applyUrlChoice(loc = globalThis.location, storage = globalThis.localStorage) {
    let choice = null;
    try {
      choice = parseChoice(loc.search);
      if (choice === null) return null;
      writeEnabled(choice, storage);
      const url = new URL(loc.href);
      url.searchParams.delete("pony");
      history.replaceState(history.state, "", url);
    } catch (e) {
      return choice;
    }
    return choice;
  }
  function readEnabled(storage = globalThis.localStorage) {
    try {
      return storage.getItem(STORAGE_KEY) !== "off";
    } catch (e) {
      return true;
    }
  }
  function writeEnabled(on, storage = globalThis.localStorage) {
    try {
      storage.setItem(STORAGE_KEY, on ? "on" : "off");
    } catch (e) {}
  }
  function labelFor(on) {
    const ru = /^ru/i.test(document.documentElement.lang || navigator.language || "");
    if (ru) return on ? "Питомец: выключить" : "Питомец: включить";
    return on ? "Pet: turn off" : "Pet: turn on";
  }
  function createToggle({ enabled, onChange }) {
    let on = enabled;
    let timer = 0;
    const style = document.createElement("style");
    style.textContent = STYLE;
    const zone = document.createElement("div");
    zone.className = "upt-zone";
    const btn = document.createElement("button");
    btn.type = "button";
    btn.className = "upt";
    btn.innerHTML = PAW;
    zone.append(btn);
    function render() {
      btn.setAttribute("aria-pressed", String(on));
      const label = labelFor(on);
      btn.setAttribute("aria-label", label);
      btn.title = label;
      if (on) zone.removeAttribute("data-off");
      else zone.setAttribute("data-off", "");
    }
    function reveal(ms) {
      clearTimeout(timer);
      btn.removeAttribute("data-hidden");
      if (ms) timer = setTimeout(hideIfOff, ms);
    }
    function hideIfOff() {
      clearTimeout(timer);
      if (!on) btn.setAttribute("data-hidden", "");
    }
    btn.addEventListener("click", () => {
      on = !on;
      writeEnabled(on);
      render();
      if (on) reveal(0);
      else hideIfOff();
      onChange(on);
    });
    zone.addEventListener("pointerenter", () => {
      if (!on) reveal(0);
    });
    zone.addEventListener("pointerleave", () => {
      if (!on) timer = setTimeout(hideIfOff, HIDE_DELAY);
    });
    zone.addEventListener("pointerdown", (e) => {
      if (!on && e.target === zone) reveal(TAP_REVEAL);
    });
    render();
    if (!on) btn.setAttribute("data-hidden", "");
    (document.head || document.documentElement).append(style);
    (document.body || document.documentElement).append(zone);
    return {
      destroy() {
        clearTimeout(timer);
        zone.remove();
        style.remove();
      },
    };
  }
  const PRESETS = {
    firc: {
      tabs: "[data-tabs-trigger]",
      switches: "[data-switch-root]",
      search: 'input[type="search"]',
      dialog: '[data-dialog-content][data-state="open"]',
      reading: 2,
    },
  };
  const CHECK_EVERY = 250;
  const POKE_FOR = 800;
  const TYPING_FOR = 1500;
  const NO_MATCH_AFTER = 700;
  function closest(target, selector) {
    try {
      return target instanceof Element && selector ? target.closest(selector) : null;
    } catch (e) {
      return null;
    }
  }
  function all(selector) {
    try {
      return selector ? [...document.querySelectorAll(selector)] : [];
    } catch (e) {
      return [];
    }
  }
  function createPage(cfg, items, now = () => performance.now()) {
    let tab = -1;
    let dialog = false;
    let checkedAt = -Infinity;
    let poke = null;
    let typedAt = -Infinity;
    let value = "";
    let searchX = 0;
    let missChecked = true;
    let events = [];
    const onPress = (e) => {
      const el = closest(e.target, cfg.switches);
      if (el) poke = { el, state: el.getAttribute("data-state"), t: now() };
    };
    const onInput = (e) => {
      if (!closest(e.target, cfg.search)) return;
      typedAt = now();
      value = e.target.value || "";
      missChecked = false;
      const r = e.target.getBoundingClientRect();
      searchX = (r.left + r.right) / 2;
    };
    const press = ["pointerdown", "click", "keydown"];
    press.forEach((n) => document.addEventListener(n, onPress, true));
    document.addEventListener("input", onInput, true);
    return {
      poll() {
        const t = now();
        if (poke) {
          const state = poke.el.getAttribute("data-state");
          if (poke.el.isConnected && state && state !== poke.state) {
            const r = poke.el.getBoundingClientRect();
            events.push({
              type: "switch",
              on: state === "checked",
              x: (r.left + r.right) / 2,
              y: (r.top + r.bottom) / 2,
            });
            poke = null;
          } else if (t - poke.t > POKE_FOR) {
            poke = null;
          }
        }
        if (t - checkedAt >= CHECK_EVERY) {
          checkedAt = t;
          const idx = all(cfg.tabs).findIndex((el) => el.getAttribute("data-state") === "active");
          if (idx !== tab) {
            if (tab !== -1 && idx !== -1) events.push({ type: "tab", index: idx });
            tab = idx;
          }
          dialog = all(cfg.dialog).length > 0;
        }
        if (!missChecked && t - typedAt >= NO_MATCH_AFTER) {
          missChecked = true;
          if (value && !all(items).some((el) => el.getClientRects().length))
            events.push({ type: "nomatch" });
        }
        const out = {
          events,
          dialog,
          reading: tab !== -1 && tab === cfg.reading,
          typing: !!value && t - typedAt < TYPING_FOR,
          searchX,
        };
        events = [];
        return out;
      },
      destroy() {
        press.forEach((n) => document.removeEventListener(n, onPress, true));
        document.removeEventListener("input", onInput, true);
      },
    };
  }
  function isHatSeason(date = new Date()) {
    const m = date.getMonth();
    const d = date.getDate();
    return (m === 11 && d >= 15) || (m === 0 && d <= 10);
  }
  const DEFAULT_SIZE = 80;
  const FRAME_CAP = 0.1;
  const LAYOUT_EVERY = 120;
  const TURN_POSE = poseAt("rear", 0.62 * ACTIONS.rear.duration);
  const TURN_REAR = 0.3;
  const HOP_ENTER = 0.12;
  const HOP_EXIT = 0.15;
  const AUTO_PLATFORMS = (document.currentScript && document.currentScript.dataset.platforms) || "";
  const AUTO_WATCH = (document.currentScript && document.currentScript.dataset.watch) || "";
  const AUTO_TOGGLE =
    !!document.currentScript && document.currentScript.hasAttribute("data-toggle");
  const AUTO_PAGE = (document.currentScript && document.currentScript.dataset.page) || "";
  const AUTO_HAT = document.currentScript
    ? { on: true, off: false }[document.currentScript.dataset.hat]
    : undefined;
  const LAYER_STYLE =
    "position:fixed;left:0;bottom:0;width:100%;height:0;overflow:visible;pointer-events:none;z-index:2147483000";
  let runtime = null;
  function viewportWidth() {
    return document.documentElement.clientWidth || window.innerWidth || 0;
  }
  function prefersReducedMotion() {
    return (
      typeof window.matchMedia === "function" &&
      window.matchMedia("(prefers-reduced-motion: reduce)").matches
    );
  }
  function startPony(opts) {
    if (runtime) return;
    const requested = opts && opts.size;
    const size = Number.isFinite(requested) && requested > 0 ? requested : DEFAULT_SIZE;
    const host = document.body || document.documentElement;
    const layer = document.createElement("div");
    layer.setAttribute("aria-hidden", "true");
    layer.style.cssText = LAYER_STYLE;
    const hat =
      opts && typeof opts.hat === "boolean"
        ? opts.hat
        : typeof AUTO_HAT === "boolean"
          ? AUTO_HAT
          : isHatSeason();
    const { el: svg, parts, front } = buildPony(size, { hat });
    let shownFront = 0;
    svg.style.cssText =
      `position:absolute;left:0;bottom:0;width:${svg.getAttribute("width")}px;height:${size}px;` +
      "max-width:none;overflow:visible;pointer-events:none;transform-origin:50% 50%;will-change:transform";
    layer.append(svg);
    host.append(layer);
    const rt = { layer, raf: 0, cleanup: [] };
    runtime = rt;
    if (prefersReducedMotion()) {
      applyPose(parts, STAND);
      return;
    }
    const director = createDirector({ width: viewportWidth(), size });
    rt.director = director;
    const dust = createDust(size);
    const dustSvg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
    dustSvg.setAttribute("aria-hidden", "true");
    dustSvg.style.cssText =
      "position:absolute;left:0;bottom:0;width:1px;height:1px;overflow:visible;pointer-events:none";
    const dots = [];
    for (let i = 0; i < DUST_CAP; i++) {
      const c = document.createElementNS("http://www.w3.org/2000/svg", "circle");
      c.setAttribute("fill", DUST_COLOR);
      c.style.display = "none";
      dustSvg.append(c);
      dots.push(c);
    }
    layer.prepend(dustSvg);
    const grass = createGrass(size);
    layer.prepend(grass.el);
    let shown = 0;
    let landed = false;
    let wasJump = false;
    const DUST_GAIT = { gallop: 1, run: 0.8, trot: 0.35 };
    const selector = opts && typeof opts.platforms === "string" ? opts.platforms : AUTO_PLATFORMS;
    let last = null;
    let plat = null;
    let base = 0;
    let hop = null;
    let cursor = null;
    let carry = null;
    const mood = createMood();
    const pageCfg = Object.hasOwn(PRESETS, opts && opts.page ? opts.page : AUTO_PAGE)
      ? PRESETS[opts && opts.page ? opts.page : AUTO_PAGE]
      : null;
    const page = pageCfg
      ? createPage(
          pageCfg,
          opts && typeof opts.platforms === "string" ? opts.platforms : AUTO_PLATFORMS,
        )
      : null;
    if (page) rt.cleanup.push(() => page.destroy());
    const watch = opts && typeof opts.watch === "string" ? opts.watch : AUTO_WATCH;
    let lastInput = performance.now();
    let hiddenAt = null;
    let returned = 0;
    let toast = null;
    let pressed = false;
    let facing = null;
    let turn = null;
    function findPlatform(groundLine) {
      if (!selector) return null;
      const rects = [];
      try {
        for (const el of document.querySelectorAll(selector)) {
          const r = el.getBoundingClientRect();
          rects.push({ el, left: r.left, right: r.right, top: r.top, bottom: r.bottom });
        }
      } catch (e) {
        return null;
      }
      return pickPlatform(rects, groundLine, 2 * size);
    }
    let layoutAt = -Infinity;
    let layoutDirty = true;
    let groundLine = 0;
    let pageWidth = 0;
    let candidate = null;
    const markLayout = () => {
      layoutDirty = true;
    };
    function frame(now) {
      if (!layer.isConnected) {
        stopPony();
        return;
      }
      const dt = last === null || !Number.isFinite(now) ? 0 : (now - last) / 1000;
      last = Number.isFinite(now) ? now : last;
      const d = Math.min(FRAME_CAP, dt);
      if (layoutDirty || now - layoutAt >= LAYOUT_EVERY || !Number.isFinite(now)) {
        layoutAt = Number.isFinite(now) ? now : 0;
        layoutDirty = false;
        groundLine = layer.getBoundingClientRect().bottom;
        pageWidth = viewportWidth();
        candidate = findPlatform(groundLine);
      }
      director.setWidth(pageWidth);
      const s = director.step(dt);
      const mid = s.x + 0.5 * WIDTH_PER_SIZE * size;
      const found = candidate;
      const next = found && mid >= found.left && mid <= found.right ? found : null;
      if ((next && next.el) !== (plat && plat.el)) hop = { t: 0, from: base, h: 0 };
      plat = next;
      const target = plat ? Math.max(0, groundLine - plat.top) : 0;
      let y;
      let pose = s.pose;
      if (hop) {
        if (!hop.h) hop.h = hopHeight(hop.from, target, size);
        hop.t += d;
        const u = Math.min(1, hop.t / HOP_TIME);
        base = hopY(u, hop.from, target, hop.h);
        y = base;
        const air = poseAt("jump", 0.9 * u);
        pose = lerpPose(s.pose, air, easeInOut(hop.t / HOP_ENTER));
        if (u >= 1) {
          hop = null;
          landed = true;
          carry = { pose: air, t: 0 };
        }
      } else {
        base = target;
        y = base + fitY(s.y, s.top, size, groundLine - base) - s.sink;
        if (carry) {
          carry.t += d;
          pose = lerpPose(carry.pose, s.pose, easeInOut(carry.t / HOP_EXIT));
          if (carry.t >= HOP_EXIT) carry = null;
        }
      }
      const bottom = groundLine - y;
      const cmd = mood({
        dt: d,
        size,
        cursor,
        box: { left: s.x, right: s.x + WIDTH_PER_SIZE * size, top: bottom - size, bottom },
        dir: s.dir,
        action: s.action,
        idle: (performance.now() - lastInput) / 1000,
        pressed,
        returned,
        toast,
        page: page ? page.poll() : undefined,
      });
      returned = 0;
      toast = null;
      if (cmd.face) director.face(cmd.face);
      if (cmd.play) director.play(cmd.play);
      else if (cmd.hold) director.hold(cmd.hold);
      else if (cmd.flee) director.flee(cmd.flee);
      else if (cmd.follow !== null) director.follow(cmd.follow);
      if (cmd.gaze && GAZE_ACTIONS.has(s.action) && !hop)
        pose = { ...pose, head: (pose.head || 0) + cmd.gaze };
      const want = s.dir === 1 ? -1 : 1;
      if (facing === null) facing = want;
      if (turn) {
        if (want !== turn.to) turn = { t: TURN_TIME - turn.t, from: turn.to, to: want };
      } else if (want !== facing) {
        turn = { t: 0, from: facing, to: want };
      }
      let sx = facing;
      let rise = 0;
      let yaw = 0;
      let fr = 0;
      if (turn) {
        turn.t += d;
        ({ sx, rise, yaw, front: fr } = turnAt(turn.t / TURN_TIME, turn.from, turn.to));
        if (turn.t >= TURN_TIME) {
          facing = turn.to;
          turn = null;
        }
        pose = lerpPose(pose, TURN_POSE, TURN_REAR * rise);
      }
      svg.style.transform = `translate(${s.x}px, ${-y - 0.05 * size * rise}px) scaleX(${sx})${yaw ? ` perspective(${6 * size}px) rotateY(${yaw.toFixed(1)}deg)` : ""}`;
      applyPose(parts, pose);
      if (fr || shownFront) {
        shownFront = fr;
        front.style.opacity = fr;
        parts.body.style.opacity = 1 - fr;
        front.style.transform = fr ? `scaleX(${(1 / Math.abs(sx)).toFixed(3)})` : "";
      }
      const strength = hop ? 0 : DUST_GAIT[s.action] || 0;
      const rear = s.x + (s.dir === 1 ? 0.15 : 0.85) * WIDTH_PER_SIZE * size;
      if (strength) dust.trail(rear, base, s.dir, strength);
      if (landed || (wasJump && s.action !== "jump" && !hop))
        dust.burst(s.x + 0.5 * WIDTH_PER_SIZE * size, base);
      landed = false;
      wasJump = s.action === "jump";
      const grazing =
        s.action === "graze" && !hop ? { time: s.time, duration: ACTIONS.graze.duration } : null;
      grass.update(d, grazing, s.x + (s.dir === 1 ? 0.8 : 0.2) * WIDTH_PER_SIZE * size, base);
      dust.update(d);
      const ps = dust.particles;
      for (let i = 0; i < ps.length; i++) {
        const c = dots[i];
        c.style.display = "";
        c.setAttribute("cx", ps[i].x.toFixed(1));
        c.setAttribute("cy", (-ps[i].y).toFixed(1));
        c.setAttribute("r", ps[i].r.toFixed(1));
        c.setAttribute("fill-opacity", ps[i].o.toFixed(2));
      }
      for (let i = ps.length; i < shown; i++) dots[i].style.display = "none";
      shown = ps.length;
      rt.raf = requestAnimationFrame(frame);
    }
    const onVisibility = () => {
      if (document.hidden) {
        hiddenAt = performance.now();
        return;
      }
      last = null;
      lastInput = performance.now();
      if (hiddenAt !== null) returned = (performance.now() - hiddenAt) / 1000;
      hiddenAt = null;
    };
    const onInput = () => {
      lastInput = performance.now();
    };
    const onMove = (e) => {
      lastInput = performance.now();
      if (e.pointerType === "mouse") cursor = { x: e.clientX, y: e.clientY };
    };
    const onDown = (e) => {
      lastInput = performance.now();
      try {
        pressed = !!watch && e.target instanceof Element && !!e.target.closest(watch);
      } catch (err) {
        pressed = false;
      }
    };
    const onUp = () => {
      pressed = false;
    };
    const onToast = (e) => {
      toast = e.detail && e.detail.type;
    };
    const onOut = (e) => {
      if (!e.relatedTarget) cursor = null;
    };
    document.addEventListener("visibilitychange", onVisibility);
    document.addEventListener("pointermove", onMove, { passive: true });
    document.addEventListener("mouseout", onOut);
    document.addEventListener("pointerdown", onDown, true);
    document.addEventListener("pointerup", onUp, true);
    document.addEventListener("pointercancel", onUp, true);
    window.addEventListener("toast", onToast);
    window.addEventListener("scroll", markLayout, { passive: true, capture: true });
    window.addEventListener("resize", markLayout, { passive: true });
    const inputEvents = ["keydown", "wheel", "touchstart", "scroll"];
    inputEvents.forEach((n) =>
      window.addEventListener(n, onInput, { passive: true, capture: true }),
    );
    rt.cleanup.push(
      () => document.removeEventListener("visibilitychange", onVisibility),
      () => document.removeEventListener("pointermove", onMove),
      () => document.removeEventListener("mouseout", onOut),
      () => document.removeEventListener("pointerdown", onDown, true),
      () => document.removeEventListener("pointerup", onUp, true),
      () => document.removeEventListener("pointercancel", onUp, true),
      () => window.removeEventListener("toast", onToast),
      () => window.removeEventListener("scroll", markLayout, { capture: true }),
      () => window.removeEventListener("resize", markLayout),
      () => inputEvents.forEach((n) => window.removeEventListener(n, onInput, { capture: true })),
    );
    rt.raf = requestAnimationFrame(frame);
  }
  function stopPony() {
    if (!runtime) return;
    const rt = runtime;
    runtime = null;
    if (rt.raf) cancelAnimationFrame(rt.raf);
    rt.cleanup.forEach((fn) => fn());
    rt.layer.remove();
  }
  function playAction(name) {
    if (runtime && runtime.director) runtime.director.play(name);
  }
  if (!window.UnicornPony) {
    window.UnicornPony = { start: startPony, stop: stopPony, play: playAction };
    const boot = () => {
      if (navigator.webdriver) return;
      if (AUTO_TOGGLE) applyUrlChoice();
      const enabled = readEnabled();
      if (AUTO_TOGGLE) createToggle({ enabled, onChange: (on) => (on ? startPony() : stopPony()) });
      if (enabled || !AUTO_TOGGLE) startPony();
    };
    if (document.readyState === "loading") {
      document.addEventListener("DOMContentLoaded", boot, { once: true });
    } else {
      boot();
    }
  }
})();
